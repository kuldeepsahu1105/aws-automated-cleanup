#!/usr/bin/env python3
"""Report, or delete after confirmation, global IAM/S3/Route 53 resources owned by one prefix."""

import argparse
import json
import re
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_cleanup import pick, prompt

ORDER = ("iam-user", "instance-profile", "iam-role", "iam-policy", "s3-bucket", "hosted-zone")


def matches(name, prefix):
    """Match the prefix as a whole '-', '_' or '.' separated token, case-insensitively."""
    return re.search(r"(^|[-_.])" + re.escape(prefix) + r"([-_.]|$)", name, re.IGNORECASE) is not None


def pages(client, operation, result, **kwargs):
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(result, [])


def item(kind, identifier, **details):
    return {"type": kind, "id": identifier, **details}


def scan(session, prefix):
    iam = session.client("iam")
    found = []
    for user in pages(iam, "list_users", "Users"):
        if matches(user["UserName"], prefix):
            found.append(item("iam-user", user["UserName"]))
    for profile in pages(iam, "list_instance_profiles", "InstanceProfiles"):
        if matches(profile["InstanceProfileName"], prefix):
            found.append(item("instance-profile", profile["InstanceProfileName"],
                              roles=[r["RoleName"] for r in profile.get("Roles", [])]))
    for role in pages(iam, "list_roles", "Roles"):
        # Service-linked roles are owned by AWS services and cannot be deleted this way.
        if matches(role["RoleName"], prefix) and not role["Path"].startswith("/aws-service-role/"):
            found.append(item("iam-role", role["RoleName"]))
    for policy in pages(iam, "list_policies", "Policies", Scope="Local"):
        if matches(policy["PolicyName"], prefix):
            found.append(item("iam-policy", policy["Arn"], name=policy["PolicyName"],
                              attachments=policy.get("AttachmentCount", 0)))
    s3 = session.client("s3")
    for bucket in s3.list_buckets().get("Buckets", []):
        if matches(bucket["Name"], prefix):
            region = s3.get_bucket_location(Bucket=bucket["Name"]).get("LocationConstraint") or "us-east-1"
            found.append(item("s3-bucket", bucket["Name"], region=region))
    route53 = session.client("route53")
    for zone in pages(route53, "list_hosted_zones", "HostedZones"):
        if zone["Name"].split(".", 1)[0].lower() == prefix.lower():
            found.append(item("hosted-zone", zone["Id"].rsplit("/", 1)[-1], name=zone["Name"],
                              private=zone.get("Config", {}).get("PrivateZone", False)))
    found.sort(key=lambda x: (ORDER.index(x["type"]), x["id"]))
    return found


def delete_user(iam, name):
    # Deactivate keys first so credentials stop working even if a later step fails.
    keys = list(pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=name))
    for key in keys:
        iam.update_access_key(UserName=name, AccessKeyId=key["AccessKeyId"], Status="Inactive")
    for key in keys:
        iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
    try:
        iam.delete_login_profile(UserName=name)
    except iam.exceptions.NoSuchEntityException:
        pass
    for cert in pages(iam, "list_signing_certificates", "Certificates", UserName=name):
        iam.delete_signing_certificate(UserName=name, CertificateId=cert["CertificateId"])
    for key in pages(iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=name):
        iam.delete_ssh_public_key(UserName=name, SSHPublicKeyId=key["SSHPublicKeyId"])
    for cred in iam.list_service_specific_credentials(UserName=name).get("ServiceSpecificCredentials", []):
        iam.delete_service_specific_credential(
            UserName=name, ServiceSpecificCredentialId=cred["ServiceSpecificCredentialId"])
    for device in pages(iam, "list_mfa_devices", "MFADevices", UserName=name):
        iam.deactivate_mfa_device(UserName=name, SerialNumber=device["SerialNumber"])
        if ":mfa/" in device["SerialNumber"]:
            iam.delete_virtual_mfa_device(SerialNumber=device["SerialNumber"])
    for policy in pages(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name):
        iam.detach_user_policy(UserName=name, PolicyArn=policy["PolicyArn"])
    for policy in pages(iam, "list_user_policies", "PolicyNames", UserName=name):
        iam.delete_user_policy(UserName=name, PolicyName=policy)
    for group in pages(iam, "list_groups_for_user", "Groups", UserName=name):
        iam.remove_user_from_group(UserName=name, GroupName=group["GroupName"])
    if iam.get_user(UserName=name)["User"].get("PermissionsBoundary"):
        iam.delete_user_permissions_boundary(UserName=name)
    iam.delete_user(UserName=name)


def delete_instance_profile(iam, name):
    profile = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
    for role in profile.get("Roles", []):
        iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=role["RoleName"])
    iam.delete_instance_profile(InstanceProfileName=name)


def delete_role(iam, name):
    for profile in pages(iam, "list_instance_profiles_for_role", "InstanceProfiles", RoleName=name):
        iam.remove_role_from_instance_profile(InstanceProfileName=profile["InstanceProfileName"], RoleName=name)
    for policy in pages(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name):
        iam.detach_role_policy(RoleName=name, PolicyArn=policy["PolicyArn"])
    for policy in pages(iam, "list_role_policies", "PolicyNames", RoleName=name):
        iam.delete_role_policy(RoleName=name, PolicyName=policy)
    if iam.get_role(RoleName=name)["Role"].get("PermissionsBoundary"):
        iam.delete_role_permissions_boundary(RoleName=name)
    iam.delete_role(RoleName=name)


def delete_policy(iam, arn):
    for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=arn):
        for user in page.get("PolicyUsers", []):
            iam.detach_user_policy(UserName=user["UserName"], PolicyArn=arn)
        for group in page.get("PolicyGroups", []):
            iam.detach_group_policy(GroupName=group["GroupName"], PolicyArn=arn)
        for role in page.get("PolicyRoles", []):
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=arn)
    for version in pages(iam, "list_policy_versions", "Versions", PolicyArn=arn):
        if not version["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=arn, VersionId=version["VersionId"])
    iam.delete_policy(PolicyArn=arn)


def delete_bucket(s3, name):
    batch = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
        for obj in page.get("Versions", []) + page.get("DeleteMarkers", []):
            batch.append({"Key": obj["Key"], "VersionId": obj["VersionId"]})
            if len(batch) == 1000:
                delete_objects(s3, name, batch)
                batch = []
    if batch:
        delete_objects(s3, name, batch)
    for upload in pages(s3, "list_multipart_uploads", "Uploads", Bucket=name):
        s3.abort_multipart_upload(Bucket=name, Key=upload["Key"], UploadId=upload["UploadId"])
    s3.delete_bucket(Bucket=name)


def delete_objects(s3, bucket, objects):
    errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects, "Quiet": True}).get("Errors")
    if errors:
        raise ValueError(f"Could not delete {len(errors)} objects from {bucket}: {errors[0]}")


def delete_parent_delegation(route53, zone_id, zone_name):
    """Remove the NS record delegating this zone from a parent public zone in the same account."""
    servers = set(route53.get_hosted_zone(Id=zone_id).get("DelegationSet", {}).get("NameServers", []))
    if not servers:
        return
    for parent in pages(route53, "list_hosted_zones", "HostedZones"):
        if parent.get("Config", {}).get("PrivateZone") or not zone_name.endswith("." + parent["Name"]):
            continue
        records = route53.list_resource_record_sets(
            HostedZoneId=parent["Id"], StartRecordName=zone_name, StartRecordType="NS", MaxItems="1"
        ).get("ResourceRecordSets", [])
        for record in records:
            values = {r["Value"].rstrip(".") for r in record.get("ResourceRecords", [])}
            if record["Name"] == zone_name and record["Type"] == "NS" and values == {s.rstrip(".") for s in servers}:
                route53.change_resource_record_sets(HostedZoneId=parent["Id"], ChangeBatch={
                    "Changes": [{"Action": "DELETE", "ResourceRecordSet": record}]})


def delete_zone(route53, zone_id, zone_name):
    delete_parent_delegation(route53, zone_id, zone_name)
    changes = [{"Action": "DELETE", "ResourceRecordSet": record}
               for record in pages(route53, "list_resource_record_sets", "ResourceRecordSets",
                                   HostedZoneId=zone_id)
               if not (record["Name"] == zone_name and record["Type"] in ("SOA", "NS"))]
    for start in range(0, len(changes), 100):
        route53.change_resource_record_sets(HostedZoneId=zone_id,
                                            ChangeBatch={"Changes": changes[start:start + 100]})
    route53.delete_hosted_zone(Id=zone_id)


def delete(session, entry):
    kind = entry["type"]
    if kind == "iam-user":
        delete_user(session.client("iam"), entry["id"])
    elif kind == "instance-profile":
        delete_instance_profile(session.client("iam"), entry["id"])
    elif kind == "iam-role":
        delete_role(session.client("iam"), entry["id"])
    elif kind == "iam-policy":
        delete_policy(session.client("iam"), entry["id"])
    elif kind == "s3-bucket":
        delete_bucket(session.client("s3", region_name=entry["region"]), entry["id"])
    elif kind == "hosted-zone":
        delete_zone(session.client("route53"), entry["id"], entry["name"])
    else:
        raise ValueError(f"Unknown resource type: {kind}")


def run(session, prefix, types, execute, confirm_account):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,}", prefix):
        raise ValueError("Prefix must be at least 3 letters, digits or hyphens.")
    account = session.client("sts").get_caller_identity()["Account"]
    if execute and confirm_account != account:
        raise ValueError(f"Deletion requires --confirm-account {account}.")
    found = [x for x in scan(session, prefix) if not types or x["type"] in types]
    result = {"account": account, "prefix": prefix, "resources": found, "deleted": [], "failed": []}
    if not execute or not found:
        return result
    if not sys.stdin.isatty():
        raise ValueError("Deletion requires an interactive terminal.")
    found = pick(found, lambda x: f"{x['type']}: {x.get('name', x['id'])}")
    if not found:
        return result
    print(f"\nSelected {len(found)} resources:", file=sys.stderr)
    for entry in found:
        print(f"  {entry['type']}: {entry.get('name', entry['id'])}", file=sys.stderr)
    if prompt(f"Type 'delete {prefix}' to continue: ") != f"delete {prefix}":
        raise ValueError("Deletion not confirmed.")
    for entry in found:
        label = f"{entry['type']}:{entry['id']}"
        try:
            delete(session, entry)
            result["deleted"].append(label)
            print(f"Deleted {label}", file=sys.stderr)
        except (BotoCoreError, ClientError, ValueError) as exc:
            result["failed"].append({"resource": label, "error": str(exc)})
            print(f"Failed {label}: {exc}", file=sys.stderr)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix", help="Resource name prefix, for example coepse")
    parser.add_argument("--profile", help="AWS shared configuration profile")
    parser.add_argument("--type", action="append", choices=ORDER, dest="types",
                        help="Limit to a resource type; repeat for more than one")
    parser.add_argument("--execute", action="store_true", help="Delete the reported resources")
    parser.add_argument("--confirm-account", help="Account ID required with --execute")
    args = parser.parse_args(argv)
    try:
        result = run(boto3.Session(profile_name=args.profile), args.prefix, args.types,
                     args.execute, args.confirm_account)
    except (BotoCoreError, ClientError, ValueError) as exc:
        print(f"Prefix cleanup failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
