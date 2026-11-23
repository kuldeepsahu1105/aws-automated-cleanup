#!/usr/bin/env python3
"""Find AWS resources that may be unused and delete explicitly selected ones."""

import argparse
import calendar
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


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


def run(session, selections, confirm_account, now):
    if not session.region_name:
        raise ValueError("Configure an AWS default region or set AWS_DEFAULT_REGION.")
    account = session.client("sts").get_caller_identity()["Account"]
    if selections and confirm_account != account:
        raise ValueError(f"Deletion requires --confirm-account {account}.")
    if confirm_account and not selections:
        raise ValueError("--confirm-account requires at least one --delete selection.")

    discovery = session.client("ec2", region_name=session.region_name)
    regions = sorted(r["RegionName"] for r in discovery.describe_regions()["Regions"])
    if not regions:
        raise ValueError("AWS returned no enabled regions; refusing to proceed.")
    candidates = []
    for region in regions:
        candidates.extend(scan_region(session.client("ec2", region_name=region), region))
        candidates.extend(scan_security_groups_and_keys(session.client("ec2", region_name=region), region))
        candidates.extend(scan_file_systems(session.client("efs", region_name=region), region))
        candidates.extend(scan_load_balancers(session, region))
    users, excluded_users = scan_users(session.client("iam"), now)
    candidates.extend(users)
    candidates.sort(key=lambda item: item["selection"])
    by_selection = {item["selection"]: item for item in candidates}

    unknown = set(selections) - by_selection.keys()
    if unknown:
        raise ValueError("Selections are not current candidates: " + ", ".join(sorted(unknown)))

    if any(by_selection[selection]["type"] in ("sg", "key-pair") for selection in selections):
        if not sys.stdin.isatty():
            raise ValueError("Security group and key pair deletion requires an interactive terminal.")

    deleted = []
    for selection in selections:
        item = by_selection[selection]
        if item["type"] in ("sg", "key-pair"):
            confirm_sensitive_deletion(selection)
        if item["type"] == "iam-user":
            fresh, _ = scan_users(session.client("iam"), datetime.now(timezone.utc))
        elif item["type"] in ("elbv2", "classic-elb", "target-group"):
            fresh = scan_load_balancers(session, item["region"])
        elif item["type"] in ("sg", "key-pair"):
            fresh = scan_security_groups_and_keys(session.client("ec2", region_name=item["region"]),
                                                  item["region"])
        elif item["type"] == "efs":
            fresh = scan_file_systems(session.client("efs", region_name=item["region"]), item["region"])
        else:
            fresh = scan_region(session.client("ec2", region_name=item["region"]), item["region"])
        if selection not in {entry["selection"] for entry in fresh}:
            raise ValueError(f"Candidate changed before deletion: {selection}; already submitted: {deleted}")
        delete_candidate(session, item)
        deleted.append(selection)
        print(f"Deletion submitted: {selection}", file=sys.stderr)
    return {"account": account, "regions": regions, "candidates": candidates,
            "excluded_iam_users": excluded_users, "deletion_submitted": deleted}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="AWS shared configuration profile")
    parser.add_argument("--delete", action="append", default=[], metavar="SELECTION",
                        help="Explicit selection from report; repeat for each resource")
    parser.add_argument("--confirm-account", help="Account ID required for deletion")
    args = parser.parse_args(argv)
    if len(args.delete) != len(set(args.delete)):
        parser.error("Duplicate --delete selections are not allowed")
    try:
        session = boto3.Session(profile_name=args.profile)
        result = run(session, args.delete, args.confirm_account, datetime.now(timezone.utc))
    except (BotoCoreError, ClientError, ValueError) as exc:
        print(f"Cleanup failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
