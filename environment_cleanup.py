#!/usr/bin/env python3
"""Report or clean up prefix-owned AWS environments, including VPC dependencies."""

import argparse
import json
import logging
import re
import sys
import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_cleanup import configure_logging, pages, pick, prompt
import prefix_cleanup


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
OWNERSHIP_TAGS = ("Prefix", "Project", "InstallPrefix", "EnvironmentName")


def owned(tags, prefixes):
    return any(tag["Key"] in OWNERSHIP_TAGS and tag["Value"] in prefixes for tag in tags)


def resource_owned(tags, prefixes, name=""):
    ownership = [tag for tag in tags if tag["Key"] in OWNERSHIP_TAGS]
    if ownership:
        return owned(ownership, prefixes)
    names = [name] + [tag["Value"] for tag in tags if tag["Key"] == "Name"]
    return any(prefix_cleanup.matches(n, p) for n in names for p in prefixes)


def resource_name(resource, fallback):
    return next((t["Value"] for t in resource.get("Tags", []) if t["Key"] == "Name"), fallback)


class VpcCleanup:
    def __init__(self, session, region, prefixes, timeout=900, interval=10):
        self.session = session
        self.region = region
        self.prefixes = prefixes
        self.timeout = timeout
        self.interval = interval
        self.ec2 = session.client("ec2", region_name=region)
        self.elbv2 = session.client("elbv2", region_name=region)
        self.elb = session.client("elb", region_name=region)
        self.efs = session.client("efs", region_name=region)
        self.asg = session.client("autoscaling", region_name=region)
        self.selected_groups = set()
        self.approved_vpc_groups = {}

    def resources(self, operation, result, vpc):
        return list(pages(self.ec2, operation, result,
                          Filters=[{"Name": "vpc-id", "Values": [vpc]}]))

    def wait(self, label, remaining):
        deadline = time.monotonic() + self.timeout
        while True:
            blockers = remaining()
            if not blockers:
                logger.info("READY | region=%s | %s", self.region, label, extra={"event": "success"})
                return
            logger.info("WAIT | %s | region=%s | remaining=%s", label, self.region,
                        json.dumps(blockers, default=str))
            if time.monotonic() >= deadline:
                raise ValueError(f"Timed out waiting for {label}: {blockers}")
            time.sleep(self.interval)

    def action(self, label, method, **kwargs):
        logger.info("DELETE/DETACH START | region=%s | %s", self.region, label)
        response = method(**kwargs)
        if response.get("Unsuccessful"):
            raise ValueError(f"{label}: {response['Unsuccessful']}")
        if response.get("ReturnCode") is False or response.get("Return") is False:
            raise ValueError(f"{label}: AWS reported that the request was unsuccessful")
        logger.info("REQUEST ACCEPTED | region=%s | %s", self.region, label, extra={"event": "success"})
        return response

    def discover(self):
        return [vpc for vpc in pages(self.ec2, "describe_vpcs", "Vpcs")
                if not vpc.get("IsDefault") and owned(vpc.get("Tags", []), self.prefixes)]

    def blockers(self, vpc):
        """Report service-owned ENIs without trying to forcibly detach them."""
        return {
            "instances": [i["InstanceId"] for r in
                          self.resources("describe_instances", "Reservations", vpc)
                          for i in r.get("Instances", []) if i["State"]["Name"] != "terminated"],
            "nat_gateways": [
                g["NatGatewayId"] for g in pages(
                    self.ec2, "describe_nat_gateways", "NatGateways",
                    Filter=[{"Name": "vpc-id", "Values": [vpc]}])
                if g["State"] not in ("deleted", "failed")],
            "load_balancers": [
                lb["LoadBalancerArn"] for lb in
                pages(self.elbv2, "describe_load_balancers", "LoadBalancers") if lb["VpcId"] == vpc
            ] + [
                lb["LoadBalancerName"] for lb in
                pages(self.elb, "describe_load_balancers", "LoadBalancerDescriptions")
                if lb.get("VPCId") == vpc],
            "network_interfaces": [
                {key: eni.get(key) for key in ("NetworkInterfaceId", "Status", "InterfaceType",
                                              "RequesterManaged", "Description", "Attachment")}
                for eni in self.resources("describe_network_interfaces", "NetworkInterfaces", vpc)
            ],
            "subnets": [s["SubnetId"] for s in self.resources("describe_subnets", "Subnets", vpc)],
            "security_groups": [s["GroupId"] for s in
                                self.resources("describe_security_groups", "SecurityGroups", vpc)
                                if s["GroupName"] != "default"],
            "route_tables": [r["RouteTableId"] for r in
                             self.resources("describe_route_tables", "RouteTables", vpc)
                             if not any(a.get("Main") for a in r.get("Associations", []))],
            "network_acls": [a["NetworkAclId"] for a in
                             self.resources("describe_network_acls", "NetworkAcls", vpc)
                             if not a["IsDefault"]],
            "endpoints": [e["VpcEndpointId"] for e in
                          self.resources("describe_vpc_endpoints", "VpcEndpoints", vpc)
                          if e["State"] != "deleted"],
        }

    def remove_autoscaling(self, vpc):
        subnets = {s["SubnetId"] for s in self.resources("describe_subnets", "Subnets", vpc)}
        selected = []
        for group in pages(self.asg, "describe_auto_scaling_groups", "AutoScalingGroups"):
            group_subnets = set(filter(None, group.get("VPCZoneIdentifier", "").split(",")))
            if group_subnets & subnets:
                if not group_subnets <= subnets:
                    raise ValueError(f"Auto Scaling group spans unselected VPCs: {group['AutoScalingGroupName']}")
                selected.append(group["AutoScalingGroupName"])
        for name in selected:
            self.action(f"Auto Scaling group {name}", self.asg.delete_auto_scaling_group,
                        AutoScalingGroupName=name, ForceDelete=True)
        if selected:
            self.wait(f"Auto Scaling groups in {vpc}",
                      lambda: [g["AutoScalingGroupName"] for g in
                               pages(self.asg, "describe_auto_scaling_groups", "AutoScalingGroups")
                               if g["AutoScalingGroupName"] in selected])

    def remove_instances(self, vpc):
        def active_instances():
            return [instance for reservation in
                    self.resources("describe_instances", "Reservations", vpc)
                    for instance in reservation["Instances"]
                    if instance["State"]["Name"] != "terminated"]

        instances = active_instances()
        for instance in instances:
            if instance.get("InstanceLifecycle") == "spot" and instance["State"]["Name"] != "shutting-down":
                raise ValueError(f"Spot instance {instance['InstanceId']} in {vpc}: "
                                 "cancel its Spot/Fleet controller before retrying")
        for instance in instances:
            identifier = instance["InstanceId"]
            if instance["State"]["Name"] == "shutting-down":
                continue
            self.ec2.modify_instance_attribute(
                InstanceId=identifier, DisableApiTermination={"Value": False})
            self.action(f"EC2 instance {identifier}", self.ec2.terminate_instances,
                        InstanceIds=[identifier])
        self.wait(f"EC2 termination in {vpc}",
                  lambda: [i["InstanceId"] for i in active_instances()])

    def remove_load_balancers(self, vpc):
        for lb in list(pages(self.elbv2, "describe_load_balancers", "LoadBalancers")):
            if lb["VpcId"] != vpc:
                continue
            arn = lb["LoadBalancerArn"]
            attributes = self.elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]
            if any(a["Key"] == "deletion_protection.enabled" and a["Value"] == "true"
                   for a in attributes):
                self.elbv2.modify_load_balancer_attributes(
                    LoadBalancerArn=arn,
                    Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}])
            self.action(f"load balancer {lb['LoadBalancerName']}", self.elbv2.delete_load_balancer,
                        LoadBalancerArn=arn)
        for lb in list(pages(self.elb, "describe_load_balancers", "LoadBalancerDescriptions")):
            if lb.get("VPCId") == vpc:
                self.action(f"Classic ELB {lb['LoadBalancerName']}", self.elb.delete_load_balancer,
                            LoadBalancerName=lb["LoadBalancerName"])

        def remaining():
            return [lb["LoadBalancerArn"] for lb in
                    pages(self.elbv2, "describe_load_balancers", "LoadBalancers") if lb["VpcId"] == vpc] + [
                lb["LoadBalancerName"] for lb in
                pages(self.elb, "describe_load_balancers", "LoadBalancerDescriptions")
                if lb.get("VPCId") == vpc]

        self.wait(f"load balancers in {vpc}", remaining)
        self.wait(f"target group detachment in {vpc}", lambda: [
            tg["TargetGroupArn"] for tg in pages(self.elbv2, "describe_target_groups", "TargetGroups")
            if tg.get("VpcId") == vpc and tg.get("LoadBalancerArns")])
        for tg in list(pages(self.elbv2, "describe_target_groups", "TargetGroups")):
            if tg.get("VpcId") == vpc:
                self.action(f"target group {tg['TargetGroupName']}", self.elbv2.delete_target_group,
                            TargetGroupArn=tg["TargetGroupArn"])

    def remove_efs_targets(self, vpc):
        for fs in pages(self.efs, "describe_file_systems", "FileSystems"):
            identifier = fs["FileSystemId"]
            targets = list(pages(self.efs, "describe_mount_targets", "MountTargets",
                                 FileSystemId=identifier))
            selected = [mt for mt in targets if mt.get("VpcId") == vpc]
            for target in selected:
                if target["LifeCycleState"] != "deleting":
                    self.action(f"EFS mount target {target['MountTargetId']}",
                                self.efs.delete_mount_target, MountTargetId=target["MountTargetId"])
            if selected:
                self.wait(f"EFS mount targets for {identifier} in {vpc}", lambda: [
                    mt["MountTargetId"] for mt in
                    pages(self.efs, "describe_mount_targets", "MountTargets", FileSystemId=identifier)
                    if mt.get("VpcId") == vpc])
                logger.info("Preserving EFS data: %s (only mount targets removed)", identifier)

    def remove_gateways_and_endpoints(self, vpc):
        gateways = list(pages(self.ec2, "describe_nat_gateways", "NatGateways",
                              Filter=[{"Name": "vpc-id", "Values": [vpc]}]))
        for nat in gateways:
            if nat["State"] not in ("deleted", "deleting", "failed"):
                self.action(f"NAT gateway {nat['NatGatewayId']}", self.ec2.delete_nat_gateway,
                            NatGatewayId=nat["NatGatewayId"])
        self.wait(f"NAT gateways in {vpc}", lambda: [
            n["NatGatewayId"] for n in pages(self.ec2, "describe_nat_gateways", "NatGateways",
                                           Filter=[{"Name": "vpc-id", "Values": [vpc]}])
            if n["State"] not in ("deleted", "failed")])
        for endpoint in self.resources("describe_vpc_endpoints", "VpcEndpoints", vpc):
            if endpoint["State"] not in ("deleted", "deleting"):
                self.action(f"VPC endpoint {endpoint['VpcEndpointId']}", self.ec2.delete_vpc_endpoints,
                            VpcEndpointIds=[endpoint["VpcEndpointId"]])
        self.wait(f"VPC endpoints in {vpc}", lambda: [
            e["VpcEndpointId"] for e in self.resources("describe_vpc_endpoints", "VpcEndpoints", vpc)
            if e["State"] != "deleted"])
        for gateway in list(pages(self.ec2, "describe_egress_only_internet_gateways",
                                  "EgressOnlyInternetGateways")):
            if any(a["VpcId"] == vpc for a in gateway.get("Attachments", [])):
                self.action(f"egress-only gateway {gateway['EgressOnlyInternetGatewayId']}",
                            self.ec2.delete_egress_only_internet_gateway,
                            EgressOnlyInternetGatewayId=gateway["EgressOnlyInternetGatewayId"])

    def remove_connections(self, vpc):
        connections = {}
        for side in ("requester", "accepter"):
            for connection in pages(self.ec2, "describe_vpc_peering_connections", "VpcPeeringConnections",
                                    Filters=[{"Name": f"{side}-vpc-info.vpc-id", "Values": [vpc]}]):
                connections[connection["VpcPeeringConnectionId"]] = connection
        for identifier, connection in connections.items():
            if connection["Status"]["Code"] not in ("deleted", "deleting", "rejected",
                                                     "failed", "expired"):
                self.action(f"VPC peering {identifier}", self.ec2.delete_vpc_peering_connection,
                            VpcPeeringConnectionId=identifier)
        def vpn_gateways():
            return self.ec2.describe_vpn_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc]}])["VpnGateways"]

        for gateway in vpn_gateways():
            identifier = gateway["VpnGatewayId"]
            if any(a["VpcId"] == vpc and a["State"] != "detached"
                   for a in gateway.get("VpcAttachments", [])):
                self.action(f"VPN gateway attachment {identifier}", self.ec2.detach_vpn_gateway,
                            VpnGatewayId=identifier, VpcId=vpc)
        self.wait(f"VPN gateway detachments in {vpc}", lambda: [
            g["VpnGatewayId"] for g in vpn_gateways()
            if any(a["VpcId"] == vpc and a["State"] != "detached"
                   for a in g.get("VpcAttachments", []))])
        # Transit Gateway routes and remote connectivity need operator review, not blanket deletion.
        attachments = list(pages(
            self.ec2, "describe_transit_gateway_vpc_attachments", "TransitGatewayVpcAttachments",
            Filters=[{"Name": "vpc-id", "Values": [vpc]}]))
        active = [a["TransitGatewayAttachmentId"] for a in attachments
                  if a["State"] not in ("deleted", "failed", "rejected")]
        if active:
            raise ValueError(f"Remove/review Transit Gateway attachments before retrying {vpc}: {active}")

    def remove_interfaces(self, vpc):
        def remaining():
            interfaces = self.resources("describe_network_interfaces", "NetworkInterfaces", vpc)
            for eni in interfaces:
                if not eni.get("RequesterManaged") and not eni.get("Attachment") and eni["Status"] == "available":
                    self.action(f"network interface {eni['NetworkInterfaceId']}",
                                self.ec2.delete_network_interface,
                                NetworkInterfaceId=eni["NetworkInterfaceId"])
            return [{key: eni.get(key) for key in ("NetworkInterfaceId", "Description", "RequesterManaged")}
                    for eni in self.resources("describe_network_interfaces", "NetworkInterfaces", vpc)]
        self.wait(f"network interfaces in {vpc}; delete their owning service if they persist", remaining)

    def allocated_addresses(self, vpc):
        interfaces = {e["NetworkInterfaceId"] for e in
                      self.resources("describe_network_interfaces", "NetworkInterfaces", vpc)}
        allocations = {
            a["AllocationId"] for a in self.ec2.describe_addresses()["Addresses"]
            if a.get("AllocationId") and a.get("NetworkInterfaceId") in interfaces
        }
        for nat in pages(self.ec2, "describe_nat_gateways", "NatGateways",
                         Filter=[{"Name": "vpc-id", "Values": [vpc]}]):
            allocations.update(a["AllocationId"] for a in nat.get("NatGatewayAddresses", [])
                               if a.get("AllocationId"))
        return allocations

    def release_addresses(self, allocations):
        # Do not release an address that has been reassigned while teardown was running.
        for address in self.ec2.describe_addresses()["Addresses"]:
            if address.get("AllocationId") not in allocations:
                continue
            if any(address.get(key) for key in ("AssociationId", "NetworkInterfaceId",
                                                "InstanceId", "ServiceManaged")):
                logger.warning("Preserving EIP %s: still associated or service-managed",
                               address["AllocationId"])
                continue
            self.action(f"Elastic IP {address['AllocationId']}", self.ec2.release_address,
                        AllocationId=address["AllocationId"])

    def remove_group_references(self, groups):
        # Remove every SG-to-SG reference first, including default-group references and cycles.
        for group in groups:
            for field, method in (("IpPermissions", self.ec2.revoke_security_group_ingress),
                                  ("IpPermissionsEgress", self.ec2.revoke_security_group_egress)):
                references = []
                for permission in group.get(field, []):
                    if permission.get("UserIdGroupPairs"):
                        references.append({key: value for key, value in permission.items()
                                           if key in ("IpProtocol", "FromPort", "ToPort", "UserIdGroupPairs")})
                if references:
                    self.action(f"SG references on {group['GroupId']}", method,
                                GroupId=group["GroupId"], IpPermissions=references)

    def remove_network(self, vpc):
        groups = self.resources("describe_security_groups", "SecurityGroups", vpc)
        if vpc in self.approved_vpc_groups:
            unapproved = {g["GroupId"] for g in groups if g["GroupName"] != "default"} - self.approved_vpc_groups[vpc]
            if unapproved:
                raise ValueError(f"Unconfirmed security groups appeared in {vpc}: {sorted(unapproved)}")
        self.remove_group_references(groups)
        for group in groups:
            if group["GroupName"] != "default":
                self.action(f"security group {group['GroupId']}", self.ec2.delete_security_group,
                            GroupId=group["GroupId"])
        for table in self.resources("describe_route_tables", "RouteTables", vpc):
            associations = table.get("Associations", [])
            if any(a.get("Main") for a in associations):
                continue
            for association in associations:
                self.action(f"route table association {association['RouteTableAssociationId']}",
                            self.ec2.disassociate_route_table,
                            AssociationId=association["RouteTableAssociationId"])
            self.action(f"route table {table['RouteTableId']}", self.ec2.delete_route_table,
                        RouteTableId=table["RouteTableId"])
        # Deleting subnets also removes their custom ACL associations.
        for subnet in self.resources("describe_subnets", "Subnets", vpc):
            self.action(f"subnet {subnet['SubnetId']}", self.ec2.delete_subnet, SubnetId=subnet["SubnetId"])
        for acl in self.resources("describe_network_acls", "NetworkAcls", vpc):
            if not acl["IsDefault"]:
                self.action(f"network ACL {acl['NetworkAclId']}", self.ec2.delete_network_acl,
                            NetworkAclId=acl["NetworkAclId"])
        for gateway in list(pages(self.ec2, "describe_internet_gateways", "InternetGateways",
                                  Filters=[{"Name": "attachment.vpc-id", "Values": [vpc]}])):
            identifier = gateway["InternetGatewayId"]
            self.action(f"internet gateway attachment {identifier}", self.ec2.detach_internet_gateway,
                        InternetGatewayId=identifier, VpcId=vpc)
            self.action(f"internet gateway {identifier}", self.ec2.delete_internet_gateway,
                        InternetGatewayId=identifier)

    def scan_extras(self, selected_vpcs):
        found = []

        def add(kind, identifier, name="", **details):
            found.append({"type": kind, "id": identifier, "name": name or identifier,
                          "region": self.region, **details})

        group_instances = set()
        vpc_subnets = {s["SubnetId"] for v in selected_vpcs
                       for s in self.resources("describe_subnets", "Subnets", v)}
        for group in pages(self.asg, "describe_auto_scaling_groups", "AutoScalingGroups"):
            group_subnets = set(filter(None, group.get("VPCZoneIdentifier", "").split(",")))
            if group_subnets & vpc_subnets:
                continue
            if resource_owned(group.get("Tags", []), self.prefixes, group["AutoScalingGroupName"]):
                add("autoscaling", group["AutoScalingGroupName"])
                group_instances.update(i["InstanceId"] for i in group.get("Instances", []))
        instances = [i for r in pages(self.ec2, "describe_instances", "Reservations")
                     for i in r.get("Instances", []) if i["State"]["Name"] != "terminated"]
        selected_instances = set()
        selected_interfaces = set()
        for instance in instances:
            if (instance.get("VpcId") in selected_vpcs or instance["InstanceId"] in group_instances
                    or resource_owned(instance.get("Tags", []), self.prefixes)):
                selected_instances.add(instance["InstanceId"])
                selected_interfaces.update(n["NetworkInterfaceId"] for n in instance.get("NetworkInterfaces", []))
                if instance.get("VpcId") not in selected_vpcs:
                    add("ec2", instance["InstanceId"], resource_name(instance, instance["InstanceId"]),
                        vpc=instance.get("VpcId"), state=instance["State"]["Name"])
        for volume in pages(self.ec2, "describe_volumes", "Volumes"):
            if resource_owned(volume.get("Tags", []), self.prefixes) or any(
                    a["InstanceId"] in selected_instances for a in volume.get("Attachments", [])):
                add("ebs", volume["VolumeId"], resource_name(volume, volume["VolumeId"]), size_gib=volume["Size"],
                    attachments=volume.get("Attachments", []))
        for address in self.ec2.describe_addresses()["Addresses"]:
            if address.get("AllocationId") and (
                    address.get("NetworkInterfaceId") in selected_interfaces
                    or resource_owned(address.get("Tags", []), self.prefixes)):
                add("eip", address["AllocationId"], address["PublicIp"])
        for key in self.ec2.describe_key_pairs()["KeyPairs"]:
            if resource_owned(key.get("Tags", []), self.prefixes, key["KeyName"]):
                add("key-pair", key["KeyPairId"], key["KeyName"])
        for group in pages(self.ec2, "describe_security_groups", "SecurityGroups"):
            if (group["GroupName"] != "default" and group["VpcId"] not in selected_vpcs
                    and resource_owned(group.get("Tags", []), self.prefixes, group["GroupName"])):
                add("sg", group["GroupId"], group["GroupName"])
        for fs in pages(self.efs, "describe_file_systems", "FileSystems"):
            if resource_owned(fs.get("Tags", []), self.prefixes, fs.get("Name", "")):
                add("efs", fs["FileSystemId"], fs.get("Name", ""))
        for operation, result, kind, id_key, name_key in (
                ("describe_load_balancers", "LoadBalancers", "elbv2", "LoadBalancerArn", "LoadBalancerName"),
                ("describe_target_groups", "TargetGroups", "target-group", "TargetGroupArn", "TargetGroupName")):
            for entry in pages(self.elbv2, operation, result):
                if entry.get("VpcId") in selected_vpcs:
                    continue
                tags = self.elbv2.describe_tags(ResourceArns=[entry[id_key]])["TagDescriptions"][0]["Tags"]
                if resource_owned(tags, self.prefixes, entry[name_key]):
                    add(kind, entry[id_key], entry[name_key])
        for lb in pages(self.elb, "describe_load_balancers", "LoadBalancerDescriptions"):
            if lb.get("VPCId") in selected_vpcs:
                continue
            tags = self.elb.describe_tags(LoadBalancerNames=[lb["LoadBalancerName"]])["TagDescriptions"][0]["Tags"]
            if resource_owned(tags, self.prefixes, lb["LoadBalancerName"]):
                add("classic-elb", lb["LoadBalancerName"])
        order = ("autoscaling", "ec2", "elbv2", "classic-elb", "target-group", "efs", "ebs", "eip", "sg", "key-pair")
        return sorted(found, key=lambda x: (order.index(x["type"]), x["id"]))

    def cleanup_extra(self, entry):
        kind, identifier = entry["type"], entry["id"]
        if kind == "autoscaling":
            groups = self.asg.describe_auto_scaling_groups(AutoScalingGroupNames=[identifier])["AutoScalingGroups"]
            if not groups:
                return False
            if not resource_owned(groups[0].get("Tags", []), self.prefixes, identifier):
                raise ValueError(f"Auto Scaling group ownership changed: {identifier}")
            self.action(f"Auto Scaling group {identifier}", self.asg.delete_auto_scaling_group,
                        AutoScalingGroupName=identifier, ForceDelete=True)
            self.wait(f"Auto Scaling group {identifier}", lambda: [
                g["AutoScalingGroupName"] for g in self.asg.describe_auto_scaling_groups(
                    AutoScalingGroupNames=[identifier])["AutoScalingGroups"]])
        elif kind == "ec2":
            response = self.ec2.describe_instances(InstanceIds=[identifier])
            instance = response["Reservations"][0]["Instances"][0]
            if instance["State"]["Name"] == "terminated":
                return False
            if instance["State"]["Name"] != "shutting-down" and not resource_owned(
                    instance.get("Tags", []), self.prefixes):
                raise ValueError(f"Instance ownership changed: {identifier}")
            # Standalone instances with a controller must be removed through that controller.
            if instance["State"]["Name"] != "shutting-down" and (
                    instance.get("InstanceLifecycle") == "spot" or any(
                        t["Key"] == "aws:autoscaling:groupName" for t in instance.get("Tags", []))):
                raise ValueError(f"{identifier} has a Spot/Auto Scaling controller; remove it first")
            if instance["State"]["Name"] != "shutting-down":
                self.ec2.modify_instance_attribute(
                    InstanceId=identifier, DisableApiTermination={"Value": False})
                self.action(f"EC2 instance {identifier}", self.ec2.terminate_instances,
                            InstanceIds=[identifier])
            self.wait(f"instance {identifier}", lambda: [
                i["InstanceId"] for r in self.ec2.describe_instances(
                    InstanceIds=[identifier])["Reservations"] for i in r["Instances"]
                if i["State"]["Name"] != "terminated"])
        elif kind == "ebs":
            volumes = self.ec2.describe_volumes(VolumeIds=[identifier])["Volumes"]
            if volumes and volumes[0].get("Attachments"):
                raise ValueError(f"Refusing to delete attached volume {identifier}")
            self.wait(f"volume {identifier} becoming available", lambda: [
                v["VolumeId"] for v in self.ec2.describe_volumes(VolumeIds=[identifier])["Volumes"]
                if v["State"] != "available"])
            self.action(f"EBS volume {identifier}", self.ec2.delete_volume, VolumeId=identifier)
        elif kind == "efs":
            fs = self.efs.describe_file_systems(FileSystemId=identifier)["FileSystems"][0]
            if not resource_owned(fs.get("Tags", []), self.prefixes, fs.get("Name", "")):
                raise ValueError(f"EFS ownership changed: {identifier}")
            targets = list(pages(self.efs, "describe_mount_targets", "MountTargets", FileSystemId=identifier))
            for target in targets:
                if target["LifeCycleState"] != "deleting":
                    self.action(f"EFS mount target {target['MountTargetId']}",
                                self.efs.delete_mount_target, MountTargetId=target["MountTargetId"])
            self.wait(f"EFS mount targets for {identifier}", lambda: [
                mt["MountTargetId"] for mt in pages(self.efs, "describe_mount_targets", "MountTargets",
                                                  FileSystemId=identifier)])
            for access_point in list(pages(self.efs, "describe_access_points", "AccessPoints",
                                           FileSystemId=identifier)):
                self.action(f"EFS access point {access_point['AccessPointId']}",
                            self.efs.delete_access_point, AccessPointId=access_point["AccessPointId"])
            self.wait(f"EFS access points for {identifier}", lambda: [
                a["AccessPointId"] for a in pages(self.efs, "describe_access_points", "AccessPoints",
                                                FileSystemId=identifier)])
            self.action(f"EFS file system {identifier}", self.efs.delete_file_system,
                        FileSystemId=identifier)
        elif kind == "eip":
            addresses = self.ec2.describe_addresses(AllocationIds=[identifier])["Addresses"]
            if addresses and any(addresses[0].get(key) for key in (
                    "AssociationId", "NetworkInterfaceId", "InstanceId", "ServiceManaged")):
                raise ValueError(f"EIP {identifier} is still associated; refusing to release")
            self.action(f"Elastic IP {identifier}", self.ec2.release_address, AllocationId=identifier)
        elif kind == "key-pair":
            instances = [i["InstanceId"] for r in pages(
                self.ec2, "describe_instances", "Reservations",
                Filters=[{"Name": "key-name", "Values": [entry["name"]]}])
                for i in r.get("Instances", []) if i["State"]["Name"] != "terminated"]
            if instances:
                raise ValueError(f"Key pair {entry['name']} is still used by instances: {instances}")
            for template in pages(self.ec2, "describe_launch_templates", "LaunchTemplates"):
                for version in pages(self.ec2, "describe_launch_template_versions", "LaunchTemplateVersions",
                                     LaunchTemplateId=template["LaunchTemplateId"]):
                    if version.get("LaunchTemplateData", {}).get("KeyName") == entry["name"]:
                        raise ValueError(f"Key pair {entry['name']} is referenced by launch template "
                                         f"{template['LaunchTemplateId']}; preserving it")
            for config in pages(self.asg, "describe_launch_configurations", "LaunchConfigurations"):
                if config.get("KeyName") == entry["name"]:
                    raise ValueError(f"Key pair {entry['name']} is referenced by launch configuration "
                                     f"{config['LaunchConfigurationName']}; preserving it")
            self.action(f"key pair {entry['name']}", self.ec2.delete_key_pair, KeyPairId=identifier)
        elif kind == "sg":
            group_ids = sorted(self.selected_groups or {identifier})
            interfaces = list(pages(self.ec2, "describe_network_interfaces", "NetworkInterfaces",
                                    Filters=[{"Name": "group-id", "Values": group_ids}]))
            if interfaces:
                raise ValueError(f"Selected security groups are still attached to ENIs: {group_ids}")
            groups = list(pages(self.ec2, "describe_security_groups", "SecurityGroups",
                                Filters=[{"Name": "group-id", "Values": group_ids}]))
            if any(g["GroupName"] == "default" for g in groups):
                raise ValueError("Refusing to delete a default security group")
            if any(not resource_owned(g.get("Tags", []), self.prefixes, g["GroupName"]) for g in groups):
                raise ValueError("Security group ownership changed; refusing to alter its rules")
            self.remove_group_references(groups)
            self.action(f"security group {identifier}", self.ec2.delete_security_group, GroupId=identifier)
            self.selected_groups.discard(identifier)
        elif kind == "elbv2":
            attrs = self.elbv2.describe_load_balancer_attributes(LoadBalancerArn=identifier)["Attributes"]
            if any(a["Key"] == "deletion_protection.enabled" and a["Value"] == "true" for a in attrs):
                self.elbv2.modify_load_balancer_attributes(
                    LoadBalancerArn=identifier,
                    Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}])
            self.action(f"load balancer {entry['name']}", self.elbv2.delete_load_balancer,
                        LoadBalancerArn=identifier)
            self.wait(f"load balancer {identifier}", lambda: [
                lb["LoadBalancerArn"] for lb in pages(self.elbv2, "describe_load_balancers", "LoadBalancers")
                if lb["LoadBalancerArn"] == identifier])
        elif kind == "classic-elb":
            self.action(f"Classic ELB {identifier}", self.elb.delete_load_balancer, LoadBalancerName=identifier)
            self.wait(f"Classic ELB {identifier}", lambda: [
                lb["LoadBalancerName"] for lb in pages(
                    self.elb, "describe_load_balancers", "LoadBalancerDescriptions")
                if lb["LoadBalancerName"] == identifier])
        elif kind == "target-group":
            groups = self.elbv2.describe_target_groups(TargetGroupArns=[identifier])["TargetGroups"]
            if groups and groups[0].get("LoadBalancerArns"):
                raise ValueError(f"Target group {identifier} still belongs to a load balancer")
            self.action(f"target group {entry['name']}", self.elbv2.delete_target_group, TargetGroupArn=identifier)
        else:
            raise ValueError(f"Unsupported resource type: {kind}")

    def cleanup(self, vpc):
        current = self.ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"][0]
        if current.get("IsDefault") or not owned(current.get("Tags", []), self.prefixes):
            raise ValueError(f"Ownership changed or default VPC selected: {vpc}")
        try:
            allocations = self.allocated_addresses(vpc)
            self.remove_connections(vpc)
            self.remove_autoscaling(vpc)
            self.remove_instances(vpc)
            self.remove_load_balancers(vpc)
            self.remove_efs_targets(vpc)
            self.remove_gateways_and_endpoints(vpc)
            self.remove_interfaces(vpc)
            self.release_addresses(allocations)
            self.remove_network(vpc)
            dependencies = self.blockers(vpc)
            if any(dependencies.values()):
                raise ValueError(f"Dependencies still present in {vpc}: {dependencies}")
            def submit_deletion():
                try:
                    self.action(f"VPC {vpc}", self.ec2.delete_vpc, VpcId=vpc)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "DependencyViolation":
                        raise
                    return self.blockers(vpc) | {"error": str(exc)}
                return []

            self.wait(f"VPC deletion request for {vpc}", submit_deletion)
        except (BotoCoreError, ClientError, ValueError):
            logger.error("VPC cleanup failed: %s region=%s", vpc, self.region)
            try:
                logger.error("Remaining dependencies: %s", json.dumps(self.blockers(vpc), default=str))
            except (BotoCoreError, ClientError, ValueError) as exc:
                logger.error("Could not retrieve remaining dependencies: %s", exc)
            raise


ABSENT_CODES = {
    "vpc": {"InvalidVpcID.NotFound"},
    "ec2": {"InvalidInstanceID.NotFound"},
    "ebs": {"InvalidVolume.NotFound", "InvalidVolumeID.NotFound"},
    "efs": {"FileSystemNotFound"},
    "eip": {"InvalidAllocationID.NotFound"},
    "sg": {"InvalidGroup.NotFound"},
    "key-pair": {"InvalidKeyPair.NotFound"},
    "elbv2": {"LoadBalancerNotFound"},
    "classic-elb": {"LoadBalancerNotFound"},
    "target-group": {"TargetGroupNotFound"},
    "s3-bucket": {"NoSuchBucket"},
    "hosted-zone": {"NoSuchHostedZone"},
}
GLOBAL_GETTERS = {
    "iam-user": ("get_user", "UserName"),
    "iam-role": ("get_role", "RoleName"),
    "instance-profile": ("get_instance_profile", "InstanceProfileName"),
    "iam-policy": ("get_policy", "PolicyArn"),
}
RETRY_CODES = {"DependencyViolation", "DeleteConflict", "ConcurrentModification",
               "BucketNotEmpty", "HostedZoneNotEmpty", "PriorRequestNotComplete"}


def global_delete(session, entry, all_regions):
    kind, identifier = entry["type"], entry["id"]
    if kind == "s3-bucket":
        account = session.client("sts").get_caller_identity()["Account"]
        prefix_cleanup.delete_bucket(session.client("s3", region_name=entry["region"]),
                                     identifier, expected_owner=account)
        return
    iam = session.client("iam")
    if kind in GLOBAL_GETTERS:
        operation, argument = GLOBAL_GETTERS[kind]
        try:
            getattr(iam, operation)(**{argument: identifier})
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                logger.info("ALREADY ABSENT | type=%s id=%s", kind, identifier)
                return False
            raise
    if kind == "iam-policy":
        # Do not detach a policy from a surviving principal, especially a shared/unselected one.
        for usage in ("PermissionsPolicy", "PermissionsBoundary"):
            for page in iam.get_paginator("list_entities_for_policy").paginate(
                    PolicyArn=identifier, PolicyUsageFilter=usage):
                if any(page.get(key) for key in ("PolicyUsers", "PolicyGroups", "PolicyRoles")):
                    raise ValueError(f"Policy {identifier} is still used as {usage}; preserving it")
    if kind == "iam-role":
        if f":assumed-role/{identifier}/" in session.client("sts").get_caller_identity().get("Arn", ""):
            raise ValueError(f"Refusing to delete the role running this cleanup: {identifier}")
        profiles = list(pages(iam, "list_instance_profiles_for_role", "InstanceProfiles", RoleName=identifier))
        if profiles:
            raise ValueError(f"Role {identifier} still has instance profiles; remove them first")
    if kind == "instance-profile":
        profile = iam.get_instance_profile(InstanceProfileName=identifier)["InstanceProfile"]
        for region in all_regions:
            ec2 = session.client("ec2", region_name=region)
            for reservation in pages(ec2, "describe_instances", "Reservations", Filters=[
                    {"Name": "iam-instance-profile.arn", "Values": [profile["Arn"]]}]):
                active = [i["InstanceId"] for i in reservation.get("Instances", [])
                          if i["State"]["Name"] != "terminated"]
                if active:
                    raise ValueError(f"Profile {identifier} is still used in {region}: {active}")
    if kind == "iam-user":
        caller = session.client("sts").get_caller_identity()
        user = iam.get_user(UserName=identifier)["User"]
        if caller.get("Arn") == user["Arn"] or caller.get("UserId", "").startswith(user["UserId"] + ":"):
            raise ValueError(f"Refusing to delete the IAM user running this cleanup: {identifier}")
    if kind == "hosted-zone" and not entry.get("private"):
        status = session.client("route53").get_dnssec(HostedZoneId=identifier)["Status"]
        if status["ServeSignature"] != "NOT_SIGNING":
            raise ValueError(f"Hosted zone {identifier} has DNSSEC enabled/in transition; "
                             "disable signing and review parent DS records before deleting")
    prefix_cleanup.delete(session, entry)


def delete_entry(entry, method, interval, timeout):
    label = f"type={entry['type']} name={entry.get('name', entry['id'])} region={entry['region']} id={entry['id']}"
    deadline = time.monotonic() + timeout
    while True:
        try:
            logger.info("DELETE START | %s", label)
            result = method()
            if result is False:
                logger.info("ALREADY COMPLETE | %s", label, extra={"event": "absent"})
                return False
            logger.info("DELETE REQUEST ACCEPTED | %s", label, extra={"event": "success"})
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ABSENT_CODES.get(entry["type"], set()):
                logger.info("ALREADY ABSENT | %s", label, extra={"event": "absent"})
                return False
            if code not in RETRY_CODES or time.monotonic() >= deadline:
                raise
            logger.warning("RETRY | %s | %s", label, exc)
            time.sleep(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", help="Limit regional resources and S3 to this region (default: all enabled)")
    parser.add_argument("--profile", help="AWS shared configuration profile")
    parser.add_argument("--prefix", action="append", required=True,
                        help="Environment prefix; repeat for more than one")
    parser.add_argument("--execute", action="store_true", help="Delete after an interactive confirmation")
    parser.add_argument("--confirm-account", help="Required account ID for deletion")
    parser.add_argument("--skip-global", action="store_true",
                        help="Skip IAM, S3 and Route 53 cleanup")
    parser.add_argument("--timeout", type=int, default=900, help="Seconds to wait per dependency (default: 900)")
    parser.add_argument("--poll-interval", type=int, default=10, help="Polling interval in seconds (default: 10)")
    parser.add_argument("--log-file", help="Also append plain-text logs to a file")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.poll_interval <= 0:
        parser.error("--timeout and --poll-interval must be positive")
    # Keep names consistent with prefix_cleanup, including global cleanup's minimum prefix length.
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,}", p) for p in args.prefix):
        parser.error("Prefixes must contain at least 3 letters, digits or hyphens")
    try:
        configure_logging(args.log_level, args.log_file)
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        if not session.region_name:
            session = boto3.Session(profile_name=args.profile, region_name="us-east-1")
        account = session.client("sts").get_caller_identity()["Account"]
        if args.execute and args.confirm_account != account:
            raise ValueError(f"Deletion requires --confirm-account {account}")
        all_regions = sorted(r["RegionName"] for r in session.client("ec2").describe_regions()["Regions"])
        if not all_regions or (args.region and args.region not in all_regions):
            raise ValueError(f"Region not enabled or no regions returned: {args.region}")
        regions = [args.region] if args.region else all_regions
        logger.info("=== ENVIRONMENT CLEANUP | account=%s prefixes=%s regions=%s ===",
                    account, ",".join(args.prefix), ",".join(regions))
        report = {"account": account, "regions": regions, "resources": [],
                  "deletion_submitted": [], "already_absent": [], "failed": [], "skipped": []}
        cleaners = {}
        for region in regions:
            logger.info("=== SCAN REGION | %s ===", region)
            cleaner = VpcCleanup(session, region, args.prefix, args.timeout, args.poll_interval)
            cleaners[region] = cleaner
            vpcs = cleaner.discover()
            for vpc in vpcs:
                report["resources"].append({
                    "type": "vpc", "id": vpc["VpcId"], "name": vpc["VpcId"], "region": region,
                    "tags": vpc.get("Tags", []), "dependencies": cleaner.blockers(vpc["VpcId"])})
            logger.info("SCAN | region=%s | EC2 EBS EFS EIP SG key-pair ELB target-group", region)
            extras = cleaner.scan_extras({v["VpcId"] for v in vpcs})
            report["resources"].extend(extras)
        if not args.skip_global:
            logger.info("=== SCAN GLOBAL | IAM S3 Route53 ===")
            for prefix in dict.fromkeys(args.prefix):
                logger.info("SCAN GLOBAL | prefix=%s | IAM S3 Route53", prefix)
                for entry in prefix_cleanup.scan(session, prefix):
                    if entry["type"] == "s3-bucket" and args.region and entry["region"] != args.region:
                        continue
                    report["resources"].append({**entry, "region": entry.get("region", "global")})
        unique = {(entry["type"], entry["region"], entry["id"]): entry for entry in report["resources"]}
        report["resources"] = list(unique.values())
        for entry in report["resources"]:
            logger.info("FOUND | %-18s | %-14s | %-30s | id=%s", entry["type"], entry["region"],
                        entry.get("name", entry["id"]), entry["id"])
        for region in regions:
            for kind in ("vpc", "autoscaling", "ec2", "ebs", "efs", "eip", "sg", "key-pair",
                         "elbv2", "classic-elb", "target-group"):
                if not any(e["type"] == kind and e["region"] == region for e in report["resources"]):
                    logger.info("NO STANDALONE MATCH | %-18s | %s (VPC dependencies listed separately)",
                                kind, region)
        if not args.skip_global:
            for kind in prefix_cleanup.ORDER:
                if not any(e["type"] == kind for e in report["resources"]):
                    logger.info("NO MATCH | %-18s | global", kind)
        if args.execute:
            if not sys.stdin.isatty():
                raise ValueError("Deletion requires an interactive terminal")
            selected = pick(report["resources"], lambda e: (
                f"{e['type']:18} {e['region']:14} {e.get('name', e['id'])}"))
            if selected:
                logger.warning("Selected VPCs include ALL their workloads; EBS/EFS/S3 deletion destroys data")
                if prompt(f"Type 'delete {account}' to confirm the selection: ") != f"delete {account}":
                    raise ValueError("Deletion not confirmed")
            approved = []
            for entry in selected:
                label = f"{entry['type']}:{entry['region']}:{entry['id']}"
                if entry["type"] in ("iam-user", "efs", "sg", "key-pair"):
                    if prompt(f"Delete {label}? [y/N] ").lower() not in ("y", "yes"):
                        logger.info("SKIPPED | %s | not confirmed", label)
                        report["skipped"].append(label)
                        continue
                if entry["type"] == "vpc":
                    groups = cleaners[entry["region"]].resources(
                        "describe_security_groups", "SecurityGroups", entry["id"])
                    groups = [g for g in groups if g["GroupName"] != "default"]
                    if any(prompt(f"Delete SG {g['GroupId']} ({g['GroupName']}) in "
                                  f"VPC {entry['id']}? [y/N] ").lower() not in ("y", "yes") for g in groups):
                        logger.warning("SKIPPED | %s | a dependent security group was not confirmed", label)
                        report["skipped"].append(label)
                        continue
                    cleaners[entry["region"]].approved_vpc_groups[entry["id"]] = {
                        g["GroupId"] for g in groups}
                approved.append(entry)
            selected = approved
            for region, cleaner in cleaners.items():
                cleaner.selected_groups = {e["id"] for e in selected
                                           if e["region"] == region and e["type"] == "sg"}
            global_types = set(prefix_cleanup.ORDER)
            regional = [e for e in selected if e["type"] not in global_types]
            global_entries = [e for e in selected if e["type"] in global_types]
            global_entries.sort(key=lambda e: prefix_cleanup.ORDER.index(e["type"]))
            for entry in regional + global_entries:
                label = f"{entry['type']}:{entry['region']}:{entry['id']}"
                regional_skipped = any(s.split(":", 1)[0] not in global_types for s in report["skipped"])
                if entry["type"] in global_types and (report["failed"] or regional_skipped):
                    logger.warning("SKIPPED | %s | prior cleanup failed or regional resources were skipped", label)
                    report["skipped"].append(label)
                    continue
                try:
                    if entry["type"] in global_types:
                        method = lambda: global_delete(session, entry, all_regions)
                    elif entry["type"] == "vpc":
                        method = lambda: cleaners[entry["region"]].cleanup(entry["id"])
                    else:
                        method = lambda: cleaners[entry["region"]].cleanup_extra(entry)
                    submitted = delete_entry(entry, method, args.poll_interval, args.timeout)
                    report["deletion_submitted" if submitted else "already_absent"].append(label)
                except (BotoCoreError, ClientError, ValueError) as exc:
                    logger.error("FAILED | %s | %s", label, exc)
                    report["failed"].append({"resource": label, "error": str(exc)})
            logger.info("=== SUMMARY | submitted=%d already_absent=%d failed=%d skipped=%d ===",
                        len(report["deletion_submitted"]), len(report["already_absent"]),
                        len(report["failed"]), len(report["skipped"]))
        else:
            logger.info("Report only; pass --execute and --confirm-account %s to delete", account)
        print(json.dumps(report, indent=2, default=str))
        return 1 if report["failed"] else 0
    except KeyboardInterrupt:
        logger.warning("Interrupted; requests already submitted may still complete. Rerun a report before retrying.")
        return 130
    except (BotoCoreError, ClientError, ValueError, OSError) as exc:
        logger.error("Cleanup failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
