#!/usr/bin/env python3
"""Find AWS resources that may be unused and delete explicitly selected ones."""

import argparse
import calendar
import json
import logging
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

TYPES = ("eip", "nat", "igw", "ebs", "sg", "key-pair", "efs", "elbv2", "classic-elb",
         "target-group", "iam-user")
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

LEVEL_COLORS = {
    logging.DEBUG: "\033[2m",
    logging.INFO: "\033[36m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
    logging.CRITICAL: "\033[1;31m",
}


class ConsoleFormatter(logging.Formatter):
    def __init__(self, color):
        super().__init__("%(asctime)s  %(levelname)-8s %(message)s", datefmt="%H:%M:%S")
        self.color = color

    def format(self, record):
        message = super().format(record)
        if self.color:
            color = LEVEL_COLORS.get(record.levelno, "")
            return f"{color}{message}\033[0m" if color else message
        return message


def months_ago(now, months):
    month = now.month - 1 - months
    year = now.year + month // 12
    month = month % 12 + 1
    return now.replace(year=year, month=month,
                       day=min(now.day, calendar.monthrange(year, month)[1]))


def pages(client, operation, result, **kwargs):
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(result, [])


def candidate(kind, identifier, region, reason, **details):
    return {
        "selection": f"{kind}:{region}:{identifier}",
        "type": kind,
        "id": identifier,
        "region": region,
        "reason": reason,
        **details,
    }


def scan_region(ec2, region):
    results = []
    for address in ec2.describe_addresses()["Addresses"]:
        if (address.get("Domain") == "vpc" and address.get("AllocationId")
                and not any(address.get(key) for key in
                            ("AssociationId", "NetworkInterfaceId", "InstanceId", "ServiceManaged"))):
            results.append(candidate("eip", address["AllocationId"], region,
                                     "Elastic IP has no association",
                                     public_ip=address["PublicIp"]))

    routed_nat_ids = {
        route["NatGatewayId"]
        for table in pages(ec2, "describe_route_tables", "RouteTables")
        for route in table.get("Routes", [])
        if route.get("NatGatewayId")
    }
    for gateway in pages(ec2, "describe_nat_gateways", "NatGateways"):
        if gateway["State"] == "available" and gateway["NatGatewayId"] not in routed_nat_ids:
            results.append(candidate("nat", gateway["NatGatewayId"], region,
                                     "Available NAT gateway has no route table references; usage is not proven"))

    for gateway in pages(ec2, "describe_internet_gateways", "InternetGateways"):
        if not gateway.get("Attachments"):
            results.append(candidate("igw", gateway["InternetGatewayId"], region,
                                     "Internet gateway is not attached to a VPC"))

    for volume in pages(ec2, "describe_volumes", "Volumes",
                        Filters=[{"Name": "status", "Values": ["available"]}]):
        if volume["State"] == "available" and not volume.get("Attachments"):
            results.append(candidate("ebs", volume["VolumeId"], region,
                                     "EBS volume is available and not attached",
                                     size_gib=volume["Size"]))
    return results


def scan_security_groups_and_keys(ec2, region):
    results = []
    attached_groups = {
        group["GroupId"]
        for interface in pages(ec2, "describe_network_interfaces", "NetworkInterfaces")
        for group in interface.get("Groups", [])
    }
    for group in pages(ec2, "describe_security_groups", "SecurityGroups"):
        if group["GroupName"] != "default" and group["GroupId"] not in attached_groups:
            results.append(candidate("sg", group["GroupId"], region,
                                     "Non-default security group not attached to a network interface",
                                     name=group["GroupName"]))

    instance_keys = {
        instance["KeyName"]
        for reservation in pages(ec2, "describe_instances", "Reservations")
        for instance in reservation.get("Instances", [])
        if instance.get("KeyName")
    }
    for key in ec2.describe_key_pairs()["KeyPairs"]:
        if key["KeyName"] not in instance_keys:
            if not key.get("KeyPairId"):
                raise ValueError(f"Key pair ID missing for {key['KeyName']} in {region}")
            results.append(candidate("key-pair", key["KeyPairId"], region,
                                     "Key pair not referenced by any visible EC2 instance",
                                     name=key["KeyName"]))
    return results


def scan_file_systems(efs, region):
    results = []
    for fs in pages(efs, "describe_file_systems", "FileSystems"):
        if fs["LifeCycleState"] != "available":
            continue
        targets = pages(efs, "describe_mount_targets", "MountTargets", FileSystemId=fs["FileSystemId"])
        if next(targets, None) is None:
            results.append(candidate("efs", fs["FileSystemId"], region,
                                     "EFS file system has no mount targets; it may still contain needed data"))
    return results


def scan_load_balancers(session, region):
    results = []
    elbv2 = session.client("elbv2", region_name=region)
    for lb in pages(elbv2, "describe_load_balancers", "LoadBalancers"):
        arn = lb["LoadBalancerArn"]
        if not list(pages(elbv2, "describe_listeners", "Listeners", LoadBalancerArn=arn)):
            results.append(candidate("elbv2", arn, region,
                                     "Load balancer has no listeners; usage is not proven",
                                     name=lb["LoadBalancerName"]))
    for group in pages(elbv2, "describe_target_groups", "TargetGroups"):
        if not group.get("LoadBalancerArns"):
            results.append(candidate("target-group", group["TargetGroupArn"], region,
                                     "Target group is not associated with a load balancer",
                                     name=group["TargetGroupName"]))
    elb = session.client("elb", region_name=region)
    for lb in pages(elb, "describe_load_balancers", "LoadBalancerDescriptions"):
        if not lb.get("ListenerDescriptions"):
            results.append(candidate("classic-elb", lb["LoadBalancerName"], region,
                                     "Classic load balancer has no listeners; usage is not proven"))
    return results


def has_service_credentials(iam, name):
    kwargs = {"UserName": name}
    while True:
        response = iam.list_service_specific_credentials(**kwargs)
        if response.get("ServiceSpecificCredentials"):
            return True
        if not response.get("IsTruncated"):
            return False
        marker = response.get("Marker")
        if not marker or marker == kwargs.get("Marker"):
            raise ValueError(f"Invalid IAM service credential pagination for {name}")
        kwargs["Marker"] = marker


def scan_users(iam, now):
    cutoff = months_ago(now, 9)
    results = []
    excluded = []
    for user in pages(iam, "list_users", "Users"):
        name = user["UserName"]
        # These credential types do not provide comparable last-used timestamps.
        if (list(pages(iam, "list_signing_certificates", "Certificates", UserName=name))
                or list(pages(iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=name))
                or has_service_credentials(iam, name)):
            excluded.append({"user": name, "reason": "Credential type lacks a comparable last-used timestamp"})
            continue

        timestamps = [user["CreateDate"]]
        if user.get("PasswordLastUsed"):
            timestamps.append(user["PasswordLastUsed"])
        for key in pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
            timestamps.append(key["CreateDate"])
            used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
            if used.get("LastUsedDate"):
                timestamps.append(used["LastUsedDate"])
        latest = max(timestamps)
        if latest < cutoff:
            results.append(candidate(
                "iam-user", name, "global",
                "No recorded console sign-in or access-key use for over nine months",
                last_observed_activity_or_creation=latest.isoformat(),
            ))
    return results, excluded


def delete_candidate(session, item):
    kind, region, identifier = item["type"], item["region"], item["id"]
    if kind == "iam-user":
        session.client("iam").delete_user(UserName=identifier)
        return
    if kind == "elbv2":
        session.client("elbv2", region_name=region).delete_load_balancer(LoadBalancerArn=identifier)
        return
    if kind == "classic-elb":
        session.client("elb", region_name=region).delete_load_balancer(LoadBalancerName=identifier)
        return
    if kind == "target-group":
        session.client("elbv2", region_name=region).delete_target_group(TargetGroupArn=identifier)
        return
    if kind == "efs":
        session.client("efs", region_name=region).delete_file_system(FileSystemId=identifier)
        return
    ec2 = session.client("ec2", region_name=region)
    if kind == "eip":
        ec2.release_address(AllocationId=identifier)
    elif kind == "nat":
        ec2.delete_nat_gateway(NatGatewayId=identifier)
    elif kind == "igw":
        ec2.delete_internet_gateway(InternetGatewayId=identifier)
    elif kind == "ebs":
        ec2.delete_volume(VolumeId=identifier)
    elif kind == "sg":
        ec2.delete_security_group(GroupId=identifier)
    elif kind == "key-pair":
        ec2.delete_key_pair(KeyPairId=identifier)
    else:
        raise ValueError(f"Unknown resource type: {kind}")


def confirm_sensitive_deletion(selection):
    print(f"Confirm deletion of {selection}. Type the exact selection to continue: ",
          end="", file=sys.stderr, flush=True)
    if sys.stdin.readline().rstrip("\r\n") != selection:
        raise ValueError(f"Deletion not confirmed: {selection}")


PER_ITEM_TYPES = ("iam-user", "efs", "key-pair", "sg")


def confirm_batch(items):
    """Confirm bulk types with one typed count; ask y/N for each per-item type. Returns approved items."""
    bulk = [i for i in items if i["type"] not in PER_ITEM_TYPES]
    single = [i for i in items if i["type"] in PER_ITEM_TYPES]
    approved = set()
    if bulk:
        print(f"\nSelected {len(bulk)} resources for deletion:", file=sys.stderr)
        for item in bulk:
            print(f"  {item['selection']}  # {item['reason']}", file=sys.stderr)
        if prompt(f"Type 'delete {len(bulk)}' to continue: ") != f"delete {len(bulk)}":
            raise ValueError("Deletion not confirmed.")
        approved.update(i["selection"] for i in bulk)
    if single:
        print(f"\nIAM users, EFS, key pairs and security groups are confirmed one at a time "
              f"({len(single)}):", file=sys.stderr)
        for number, item in enumerate(single, 1):
            reply = prompt(f"[{number}/{len(single)}] delete {item['selection']}  # {item['reason']}? [y/N/q] ")
            if reply.lower() == "q":
                break
            if reply.lower() in ("y", "yes"):
                approved.add(item["selection"])
    return [i["selection"] for i in items if i["selection"] in approved]


def filter_chooser(types, regions):
    def choose(candidates):
        return [c["selection"] for c in candidates
                if (not types or c["type"] in types) and (not regions or c["region"] in regions)]
    return choose


def parse_ranges(text, count):
    text = text.strip().lower()
    if text == "all":
        return list(range(count))
    chosen = set()
    for part in filter(None, (p.strip() for p in text.split(","))):
        start, _, end = part.partition("-")
        try:
            first, last = int(start), int(end or start)
        except ValueError:
            raise ValueError(f"Invalid selection: {part}") from None
        if not 1 <= first <= last <= count:
            raise ValueError(f"Invalid selection range: {part}")
        chosen.update(range(first - 1, last))
    return sorted(chosen)


def prompt(message):
    print(message, end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().strip()


def pick(items, label):
    """Numbered menu: 'all', ranges/commas like 1-5,8, 'ask' for y/n per item, blank for none."""
    if not items:
        return []
    for number, item in enumerate(items, 1):
        print(f"{number:4}. {label(item)}", file=sys.stderr)
    answer = prompt("Delete which? 'all', numbers/ranges (e.g. 1-5,8), 'ask' for each, blank for none: ")
    if answer.lower() == "ask":
        chosen = []
        for number, item in enumerate(items, 1):
            reply = prompt(f"[{number}/{len(items)}] delete {label(item)}? [y/N/q] ").lower()
            if reply == "q":
                break
            if reply in ("y", "yes"):
                chosen.append(item)
        return chosen
    try:
        return [items[i] for i in parse_ranges(answer, len(items))]
    except ValueError as exc:
        raise ValueError(f"Invalid menu input: {exc}") from None


def interactive_chooser(candidates):
    return [c["selection"] for c in pick(candidates, lambda c: f"{c['selection']}  # {c['reason']}")]


def read_plan(path):
    with open(path, encoding="utf-8") as handle:
        lines = [line.split("#", 1)[0].strip() for line in handle]
    selections = [line for line in lines if line]
    if len(selections) != len(set(selections)):
        raise ValueError(f"Duplicate selections in {path}")
    return lambda candidates: selections


def write_plan(path, candidates):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Delete the lines for resources you want to KEEP, then run:\n"
                     f"#   aws_cleanup.py --from-file {path} --confirm-account <account>\n")
        for item in candidates:
            handle.write(f"{item['selection']}  # {item['reason']}\n")


def fresh_selections(session, item, cache):
    kind, region = item["type"], item["region"]
    if kind == "iam-user":
        group = "iam"
    elif kind in ("elbv2", "classic-elb", "target-group"):
        group = "lb"
    elif kind in ("sg", "key-pair"):
        group = "sg"
    elif kind == "efs":
        group = "efs"
    else:
        group = "ec2"
    key = (group, region)
    if key not in cache:
        if group == "iam":
            fresh, _ = scan_users(session.client("iam"), datetime.now(timezone.utc))
        elif group == "lb":
            fresh = scan_load_balancers(session, region)
        elif group == "sg":
            fresh = scan_security_groups_and_keys(session.client("ec2", region_name=region), region)
        elif group == "efs":
            fresh = scan_file_systems(session.client("efs", region_name=region), region)
        else:
            fresh = scan_region(session.client("ec2", region_name=region), region)
        cache[key] = {entry["selection"] for entry in fresh}
    return cache[key]


def log_scan_results(scope, candidates, types):
    for kind in types:
        logger.debug("Checking scan results for %s in %s", kind, scope)
        found = [item for item in candidates if item["type"] == kind]
        if not found:
            logger.info("Not found: %s in %s", kind, scope)
            continue
        logger.info("Found %d %s candidate(s) in %s", len(found), kind, scope)
        for item in found:
            name = item.get("name", item["id"])
            logger.info("Found candidate: type=%s name=%s region=%s selection=%s",
                        kind, name, item["region"], item["selection"])
            logger.debug("Candidate details: %r", item)


def run(session, selections, confirm_account, now, chooser=None, plan_path=None, region=None):
    discovery_region = region or session.region_name
    if not discovery_region:
        raise ValueError("Configure an AWS default region or set AWS_DEFAULT_REGION.")
    account = session.client("sts", region_name=discovery_region).get_caller_identity()["Account"]
    logger.info("Starting AWS cleanup scan for account %s", account)
    deleting = bool(selections) or chooser is not None
    if deleting and confirm_account != account:
        raise ValueError(f"Deletion requires --confirm-account {account}.")
    if confirm_account and not deleting:
        raise ValueError("--confirm-account requires a deletion selection.")
    if chooser is not None and not sys.stdin.isatty():
        raise ValueError("Bulk deletion requires an interactive terminal.")

    discovery = session.client("ec2", region_name=discovery_region)
    enabled_regions = sorted(r["RegionName"] for r in discovery.describe_regions()["Regions"])
    if not enabled_regions:
        raise ValueError("AWS returned no enabled regions; refusing to proceed.")
    if region and region not in enabled_regions:
        raise ValueError(f"Region {region} is not enabled for this account.")
    regions = [region] if region else enabled_regions
    if region:
        logger.info("Region filter set to %s; scanning only that region", region)
    logger.info("Scanning %d enabled AWS regions", len(regions))
    candidates = []
    regional_types = tuple(kind for kind in TYPES if kind != "iam-user")
    for region in regions:
        logger.info("Scanning region %s", region)
        region_start = len(candidates)
        try:
            logger.info("  Scan: Elastic IPs, NAT gateways, internet gateways, EBS volumes")
            candidates.extend(scan_region(session.client("ec2", region_name=region), region))
            logger.info("  Scan: security groups and EC2 key pairs")
            candidates.extend(scan_security_groups_and_keys(session.client("ec2", region_name=region), region))
            logger.info("  Scan: EFS file systems and mount targets")
            candidates.extend(scan_file_systems(session.client("efs", region_name=region), region))
            logger.info("  Scan: load balancers, listeners, and target groups")
            candidates.extend(scan_load_balancers(session, region))
        except (BotoCoreError, ClientError, ValueError) as exc:
            logger.error("Scan failed in region %s; refusing partial results: %s", region, exc)
            raise
        log_scan_results(region, candidates[region_start:], regional_types)
        logger.info("Region scan complete: %d candidate(s) in %s",
                    len(candidates) - region_start, region)
    logger.info("Scanning global IAM users")
    users, excluded_users = scan_users(session.client("iam"), now)
    candidates.extend(users)
    log_scan_results("global", users, ("iam-user",))
    for excluded in excluded_users:
        logger.info("Not assessed: IAM user %s (%s)", excluded["user"], excluded["reason"])
    candidates.sort(key=lambda item: item["selection"])
    logger.info("Found %d IAM candidates; excluded %d users with unassessed credentials",
                len(users), len(excluded_users))
    logger.info("Scan complete: %d candidates across %d regions", len(candidates), len(regions))
    by_selection = {item["selection"]: item for item in candidates}
    if plan_path:
        write_plan(plan_path, candidates)
        logger.info("Wrote candidate plan to %s", plan_path)
    if chooser is not None:
        selections = chooser(candidates)

    unknown = set(selections) - by_selection.keys()
    if unknown:
        raise ValueError("Selections are not current candidates: " + ", ".join(sorted(unknown)))

    if chooser is not None:
        if selections:
            selections = confirm_batch([by_selection[s] for s in selections])
    elif any(by_selection[selection]["type"] in ("sg", "key-pair") for selection in selections):
        if not sys.stdin.isatty():
            raise ValueError("Security group and key pair deletion requires an interactive terminal.")

    deleted = []
    cache = {}
    for selection in selections:
        item = by_selection[selection]
        name = item.get("name", item["id"])
        if chooser is None and item["type"] in ("sg", "key-pair"):
            confirm_sensitive_deletion(selection)
        if selection not in fresh_selections(session, item, cache):
            logger.warning("Candidate no longer qualifies; skipping remaining deletion batch: "
                           "type=%s name=%s region=%s selection=%s",
                           item["type"], name, item["region"], selection)
            raise ValueError(f"Candidate changed before deletion: {selection}; already submitted: {deleted}")
        logger.info("Deleting candidate: type=%s name=%s region=%s selection=%s",
                    item["type"], name, item["region"], selection)
        try:
            delete_candidate(session, item)
        except (BotoCoreError, ClientError, ValueError) as exc:
            logger.error("Deletion failed: type=%s name=%s region=%s selection=%s: %s",
                         item["type"], name, item["region"], selection, exc)
            raise
        deleted.append(selection)
        logger.info("Deletion request submitted successfully: type=%s name=%s region=%s selection=%s",
                    item["type"], name, item["region"], selection)
    if not deleted:
        logger.info("No deletion requests submitted")
    else:
        logger.info("Deletion run complete: %d requests submitted", len(deleted))
    return {"account": account, "regions": regions, "candidates": candidates,
            "excluded_iam_users": excluded_users, "deletion_submitted": deleted}


def configure_logging(level, log_file=None):
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ConsoleFormatter(
        color=sys.stderr.isatty() and "NO_COLOR" not in os.environ
    ))
    handlers = [console]
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
        ))
        handlers.append(file_handler)
    logging.basicConfig(
        level=getattr(logging, level),
        handlers=handlers,
        force=True,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="AWS shared configuration profile")
    parser.add_argument("--region", help="Scan only this AWS region (default: all enabled regions)")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"),
                        default="INFO", help="Logging verbosity (default: INFO)")
    parser.add_argument("--log-file", help="Also write logs to this file")
    parser.add_argument("--delete", action="append", default=[], metavar="SELECTION",
                        help="Explicit selection from report; repeat for each resource")
    parser.add_argument("--confirm-account", help="Account ID required for deletion")
    bulk = parser.add_argument_group("bulk deletion (preview + typed confirmation, interactive terminal)")
    bulk.add_argument("--delete-all", action="store_true", help="Select every candidate (narrow with filters)")
    bulk.add_argument("--delete-type", action="append", default=[], metavar="TYPE", choices=TYPES,
                      help="Select candidates of this type; repeat for more")
    bulk.add_argument("--delete-region", action="append", default=[], metavar="REGION",
                      help="Select candidates in this region; repeat for more")
    bulk.add_argument("--interactive", action="store_true", help="Pick candidates from a numbered menu")
    bulk.add_argument("--from-file", metavar="PATH", help="Delete selections listed in a plan file")
    parser.add_argument("--write-plan", metavar="PATH", help="Write candidates to an editable plan file")
    args = parser.parse_args(argv)
    try:
        configure_logging(args.log_level, args.log_file)
    except OSError as exc:
        print(f"Could not configure logging: {exc}", file=sys.stderr)
        return 1
    if len(args.delete) != len(set(args.delete)):
        parser.error("Duplicate --delete selections are not allowed")
    filtering = args.delete_all or args.delete_type or args.delete_region
    modes = [bool(args.delete), bool(filtering), args.interactive, bool(args.from_file)]
    if sum(modes) > 1:
        parser.error("Use only one of --delete, --delete-all/--delete-type/--delete-region, "
                     "--interactive or --from-file")
    try:
        chooser = None
        if filtering:
            chooser = filter_chooser(set(args.delete_type), set(args.delete_region))
        elif args.interactive:
            chooser = interactive_chooser
        elif args.from_file:
            chooser = read_plan(args.from_file)
        session = boto3.Session(profile_name=args.profile)
        result = run(session, args.delete, args.confirm_account, datetime.now(timezone.utc),
                     chooser, args.write_plan, args.region)
    except (BotoCoreError, ClientError, ValueError, OSError) as exc:
        logger.error("Cleanup failed: %s", exc)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
