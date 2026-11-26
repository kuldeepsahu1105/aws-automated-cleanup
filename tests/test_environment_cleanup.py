import io
import json
import unittest
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import environment_cleanup as cleanup


class VpcCleanupTests(unittest.TestCase):
    def setUp(self):
        self.ec2 = Mock()
        self.session = Mock()
        self.session.client.side_effect = lambda name, **kwargs: self.ec2 if name == "ec2" else Mock()
        self.cleaner = cleanup.VpcCleanup(self.session, "us-east-2", ["example"], timeout=1, interval=1)

    def test_exact_ownership_and_default_vpc_exclusion(self):
        vpcs = [
            {"VpcId": "vpc-owned", "Tags": [{"Key": "Prefix", "Value": "example"}]},
            {"VpcId": "vpc-other", "Tags": [{"Key": "Prefix", "Value": "example-other"}]},
            {"VpcId": "vpc-default", "IsDefault": True,
             "Tags": [{"Key": "Project", "Value": "example"}]},
        ]
        with patch.object(cleanup, "pages", return_value=iter(vpcs)):
            self.assertEqual(self.cleaner.discover(), [vpcs[0]])

    def test_explicit_foreign_tags_override_a_matching_name(self):
        self.assertFalse(cleanup.resource_owned(
            [{"Key": "Prefix", "Value": "other"}], ["example"], "example-volume"))
        self.assertTrue(cleanup.resource_owned(
            [{"Key": "Name", "Value": "artifact-example-data"}], ["example"]))
        self.assertFalse(cleanup.resource_owned([], ["example"], "example2-data"))

    def test_attached_volume_is_never_detached_or_deleted(self):
        self.ec2.describe_volumes.return_value = {"Volumes": [
            {"VolumeId": "vol-1", "Attachments": [{"InstanceId": "i-other"}]}]}
        with self.assertRaisesRegex(ValueError, "attached volume"):
            self.cleaner.cleanup_extra({"type": "ebs", "id": "vol-1"})
        self.ec2.detach_volume.assert_not_called()
        self.ec2.delete_volume.assert_not_called()

    def test_regional_scan_covers_ec2_volumes_efs_keypairs_eips_and_security_groups(self):
        data = {
            "describe_auto_scaling_groups": [],
            "describe_instances": [{"Instances": [
                {"InstanceId": "i-owned", "VpcId": "vpc-unselected", "State": {"Name": "running"},
                 "Tags": [{"Key": "Name", "Value": "example-worker"}],
                 "NetworkInterfaces": [{"NetworkInterfaceId": "eni-owned"}]},
                {"InstanceId": "i-other", "State": {"Name": "running"}},
            ]}],
            "describe_volumes": [
                {"VolumeId": "vol-child", "Size": 10, "Attachments": [{"InstanceId": "i-owned"}]},
                {"VolumeId": "vol-owned", "Size": 5, "Tags": [{"Key": "Prefix", "Value": "example"}]},
                {"VolumeId": "vol-other", "Size": 5},
            ],
            "describe_security_groups": [
                {"GroupId": "sg-default", "GroupName": "default", "VpcId": "vpc-unselected",
                 "Tags": [{"Key": "Prefix", "Value": "example"}]},
                {"GroupId": "sg-owned", "GroupName": "example-worker", "VpcId": "vpc-unselected"},
                {"GroupId": "sg-other", "GroupName": "example-shared", "VpcId": "vpc-unselected",
                 "Tags": [{"Key": "Prefix", "Value": "other"}]},
            ],
            "describe_file_systems": [{"FileSystemId": "fs-owned",
                                       "Tags": [{"Key": "Prefix", "Value": "example"}]}],
            "describe_load_balancers": [],
            "describe_target_groups": [],
        }
        self.ec2.describe_key_pairs.return_value = {"KeyPairs": [
            {"KeyPairId": "key-owned", "KeyName": "example-key"}]}
        self.ec2.describe_addresses.return_value = {"Addresses": [
            {"AllocationId": "eip-owned", "PublicIp": "192.0.2.1", "NetworkInterfaceId": "eni-owned"}]}
        with patch.object(cleanup, "pages", side_effect=lambda client, op, result, **kwargs: data[op]):
            found = self.cleaner.scan_extras(set())
        self.assertEqual({e["id"] for e in found}, {
            "i-owned", "vol-child", "vol-owned", "sg-owned", "fs-owned", "eip-owned", "key-owned"})
        self.ec2.terminate_instances.assert_not_called()

    def test_policy_attached_to_a_surviving_principal_is_preserved(self):
        iam = Mock()
        session = Mock()
        session.client.return_value = iam
        iam.get_paginator.return_value.paginate.return_value = [
            {"PolicyUsers": [{"UserName": "other-user"}]}]
        with patch("environment_cleanup.prefix_cleanup.delete") as delete:
            with self.assertRaisesRegex(ValueError, "still used"):
                cleanup.global_delete(session, {"type": "iam-policy", "id": "arn:policy"}, [])
        delete.assert_not_called()
        iam.detach_user_policy.assert_not_called()

    def test_already_deleted_resource_is_a_successful_noop(self):
        operation = Mock(side_effect=ClientError(
            {"Error": {"Code": "InvalidVolume.NotFound", "Message": "gone"}}, "DeleteVolume"))
        with self.assertLogs("environment_cleanup", level="INFO") as logs:
            cleanup.delete_entry({"type": "ebs", "id": "vol-gone", "region": "us-east-2"},
                                 operation, 1, 10)
        operation.assert_called_once()
        self.assertIn("ALREADY ABSENT", "\n".join(logs.output))

    def test_wait_is_bounded_and_reports_blockers(self):
        with patch("environment_cleanup.time.monotonic", side_effect=[0, 0, 1]), \
                patch("environment_cleanup.time.sleep") as sleep, \
                self.assertLogs("environment_cleanup", level="INFO") as logs:
            with self.assertRaisesRegex(ValueError, "eni-blocker"):
                self.cleaner.wait("network interfaces", lambda: ["eni-blocker"])
        sleep.assert_called_once_with(1)
        self.assertIn("eni-blocker", "\n".join(logs.output))

    def test_connections_use_valid_ec2_requests_and_both_peering_directions(self):
        ec2 = boto3.client("ec2", region_name="us-east-2",
                           aws_access_key_id="testing", aws_secret_access_key="testing")
        self.cleaner.ec2 = ec2
        with Stubber(ec2) as stub:
            for side in ("requester", "accepter"):
                stub.add_response("describe_vpc_peering_connections", {"VpcPeeringConnections": []},
                                  {"Filters": [{"Name": f"{side}-vpc-info.vpc-id", "Values": ["vpc-1"]}]})
            for _ in range(2):
                stub.add_response("describe_vpn_gateways", {"VpnGateways": []},
                                  {"Filters": [{"Name": "attachment.vpc-id", "Values": ["vpc-1"]}]})
            stub.add_response("describe_transit_gateway_vpc_attachments", {"TransitGatewayVpcAttachments": []},
                              {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]})
            self.cleaner.remove_connections("vpc-1")
            stub.assert_no_pending_responses()

    def test_failed_api_batch_does_not_log_success(self):
        self.ec2.delete_vpc_endpoints.return_value = {"Unsuccessful": [
            {"ResourceId": "vpce-1", "Error": {"Code": "UnauthorizedOperation"}}]}
        with self.assertLogs("environment_cleanup", level="INFO") as logs:
            with self.assertRaisesRegex(ValueError, "UnauthorizedOperation"):
                self.cleaner.action("endpoint", self.ec2.delete_vpc_endpoints,
                                    VpcEndpointIds=["vpce-1"])
        self.assertNotIn("REQUEST ACCEPTED", "\n".join(logs.output))

    def test_network_cleanup_breaks_cycles_and_removes_unassociated_route_tables(self):
        pair = [{"GroupId": "sg-other"}]
        self.cleaner.resources = Mock(side_effect=lambda operation, result, vpc: {
            "describe_security_groups": [
                {"GroupId": "sg-default", "GroupName": "default",
                 "IpPermissions": [{"IpProtocol": "-1", "UserIdGroupPairs": pair}]},
                {"GroupId": "sg-custom", "GroupName": "custom",
                 "IpPermissionsEgress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                           "UserIdGroupPairs": pair,
                                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            ],
            "describe_route_tables": [
                {"RouteTableId": "rtb-main", "Associations": [{"Main": True}]},
                {"RouteTableId": "rtb-unused", "Associations": []},
                {"RouteTableId": "rtb-custom", "Associations": [
                    {"Main": False, "RouteTableAssociationId": "rtbassoc-1"}]},
            ],
            "describe_subnets": [{"SubnetId": "subnet-1"}],
            "describe_network_acls": [{"NetworkAclId": "acl-default", "IsDefault": True},
                                      {"NetworkAclId": "acl-custom", "IsDefault": False}],
        }[operation])
        for name in ("revoke_security_group_ingress", "revoke_security_group_egress",
                     "delete_security_group", "disassociate_route_table", "delete_route_table",
                     "delete_subnet", "delete_network_acl"):
            getattr(self.ec2, name).return_value = {}
        with patch.object(cleanup, "pages", return_value=[]):
            self.cleaner.remove_network("vpc-1")
        self.ec2.delete_security_group.assert_called_once_with(GroupId="sg-custom")
        self.ec2.revoke_security_group_egress.assert_called_once_with(
            GroupId="sg-custom", IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": pair}])
        self.assertEqual(
            [call.kwargs["RouteTableId"] for call in self.ec2.delete_route_table.call_args_list],
            ["rtb-unused", "rtb-custom"])
        calls = [call[0] for call in self.ec2.method_calls]
        self.assertLess(calls.index("revoke_security_group_egress"), calls.index("delete_security_group"))
        self.assertLess(calls.index("delete_subnet"), calls.index("delete_network_acl"))
        self.ec2.delete_network_acl.assert_called_once_with(NetworkAclId="acl-custom")

    def test_requester_managed_enis_are_not_forcibly_detached_or_deleted(self):
        managed = {"NetworkInterfaceId": "eni-service", "RequesterManaged": True,
                   "Status": "available", "Description": "RDSNetworkInterface"}
        free = {"NetworkInterfaceId": "eni-free", "RequesterManaged": False, "Status": "available"}
        self.cleaner.resources = Mock(side_effect=[[managed, free], [managed]])
        self.ec2.delete_network_interface.return_value = {}
        self.cleaner.wait = lambda label, remaining: self.assertEqual(
            remaining()[0]["NetworkInterfaceId"], "eni-service")
        self.cleaner.remove_interfaces("vpc-1")
        self.ec2.delete_network_interface.assert_called_once_with(NetworkInterfaceId="eni-free")
        self.ec2.detach_network_interface.assert_not_called()

    def test_load_balancers_finish_deleting_before_target_groups(self):
        lb = {"VpcId": "vpc-1", "LoadBalancerArn": "arn:lb", "LoadBalancerName": "example-lb"}
        classic = {"VPCId": "vpc-1", "LoadBalancerName": "example-classic"}
        tg = {"VpcId": "vpc-1", "TargetGroupArn": "arn:tg", "TargetGroupName": "example-tg"}
        lb_pages = iter([[lb], [lb], []])
        classic_pages = iter([[classic], [classic], []])
        tg_pages = iter([[{**tg, "LoadBalancerArns": ["arn:lb"]}], [tg], [tg]])
        self.cleaner.elbv2.describe_load_balancer_attributes.return_value = {
            "Attributes": [{"Key": "deletion_protection.enabled", "Value": "true"}]}
        self.cleaner.elbv2.delete_load_balancer.return_value = {}
        self.cleaner.elb.delete_load_balancer.return_value = {}
        self.cleaner.elbv2.delete_target_group.return_value = {}

        def fake_pages(client, operation, result, **kwargs):
            if operation == "describe_target_groups":
                return next(tg_pages)
            return next(lb_pages if client is self.cleaner.elbv2 else classic_pages)

        with patch.object(cleanup, "pages", side_effect=fake_pages), \
                patch("environment_cleanup.time.sleep") as sleep:
            self.cleaner.remove_load_balancers("vpc-1")
        self.assertEqual(sleep.call_count, 2)
        self.cleaner.elb.delete_load_balancer.assert_called_once_with(LoadBalancerName="example-classic")
        self.cleaner.elbv2.modify_load_balancer_attributes.assert_called_once()
        self.cleaner.elbv2.delete_target_group.assert_called_once_with(TargetGroupArn="arn:tg")

    def test_efs_only_mount_targets_in_selected_vpc_are_deleted(self):
        filesystem = {"FileSystemId": "fs-1"}
        target = {"MountTargetId": "fsmt-owned", "VpcId": "vpc-1", "LifeCycleState": "available"}
        other = {"MountTargetId": "fsmt-other", "VpcId": "vpc-other", "LifeCycleState": "available"}
        reads = iter([[target, other], [{**target, "LifeCycleState": "deleting"}, other], [other]])
        self.cleaner.efs.delete_mount_target.return_value = {}

        def fake_pages(client, operation, result, **kwargs):
            return [filesystem] if operation == "describe_file_systems" else next(reads)

        with patch.object(cleanup, "pages", side_effect=fake_pages), \
                patch("environment_cleanup.time.sleep") as sleep:
            self.cleaner.remove_efs_targets("vpc-1")
        sleep.assert_called_once()
        self.cleaner.efs.delete_mount_target.assert_called_once_with(MountTargetId="fsmt-owned")
        self.cleaner.efs.delete_file_system.assert_not_called()

    def test_selected_efs_mounts_and_access_points_finish_before_data_deletion(self):
        self.cleaner.efs.describe_file_systems.return_value = {"FileSystems": [
            {"FileSystemId": "fs-1", "Tags": [{"Key": "Prefix", "Value": "example"}]}]}
        target = {"MountTargetId": "fsmt-1", "LifeCycleState": "available"}
        mounts = iter([[target], [{**target, "LifeCycleState": "deleting"}], []])
        points = iter([[{"AccessPointId": "fsap-1"}], [{"AccessPointId": "fsap-1"}], []])
        for operation in ("delete_mount_target", "delete_access_point", "delete_file_system"):
            getattr(self.cleaner.efs, operation).return_value = {}

        def fake_pages(client, operation, result, **kwargs):
            return next(mounts if operation == "describe_mount_targets" else points)

        with patch.object(cleanup, "pages", side_effect=fake_pages), \
                patch("environment_cleanup.time.sleep"):
            self.cleaner.cleanup_extra({"type": "efs", "id": "fs-1"})
        calls = [call[0] for call in self.cleaner.efs.method_calls]
        self.assertLess(calls.index("delete_mount_target"), calls.index("delete_access_point"))
        self.assertLess(calls.index("delete_access_point"), calls.index("delete_file_system"))

    def test_endpoint_and_nat_deletion_are_polled(self):
        nat_reads = iter([
            [{"NatGatewayId": "nat-1", "State": "available"}],
            [{"NatGatewayId": "nat-1", "State": "deleting"}],
            [{"NatGatewayId": "nat-1", "State": "deleted"}],
        ])
        endpoint_reads = iter([
            [{"VpcEndpointId": "vpce-1", "State": "available"}],
            [{"VpcEndpointId": "vpce-1", "State": "deleting"}],
            [],
        ])
        self.cleaner.resources = Mock(side_effect=lambda *args: next(endpoint_reads))
        self.ec2.delete_nat_gateway.return_value = {}
        self.ec2.delete_vpc_endpoints.return_value = {"Unsuccessful": []}

        def fake_pages(client, operation, result, **kwargs):
            return next(nat_reads) if operation == "describe_nat_gateways" else []

        with patch.object(cleanup, "pages", side_effect=fake_pages), \
                patch("environment_cleanup.time.sleep") as sleep:
            self.cleaner.remove_gateways_and_endpoints("vpc-1")
        self.assertEqual(sleep.call_count, 2)
        self.ec2.delete_nat_gateway.assert_called_once_with(NatGatewayId="nat-1")
        self.ec2.delete_vpc_endpoints.assert_called_once_with(VpcEndpointIds=["vpce-1"])

    def test_vpc_deleted_only_after_dependency_cleanup_and_no_blockers(self):
        self.ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-1", "Tags": [{"Key": "Prefix", "Value": "example"}]}]}
        self.cleaner.allocated_addresses = Mock(return_value=set())
        stages = ("remove_connections", "remove_autoscaling", "remove_instances",
                  "remove_load_balancers", "remove_efs_targets", "remove_gateways_and_endpoints",
                  "remove_interfaces", "release_addresses", "remove_network")
        timeline = Mock()
        for stage in stages:
            method = Mock()
            setattr(self.cleaner, stage, method)
            timeline.attach_mock(method, stage)
        timeline.attach_mock(self.ec2.delete_vpc, "delete_vpc")
        self.ec2.delete_vpc.return_value = {}
        self.cleaner.blockers = Mock(return_value={"network_interfaces": []})
        self.cleaner.cleanup("vpc-1")
        self.assertEqual([call[0] for call in timeline.mock_calls], [*stages, "delete_vpc"])
        self.ec2.delete_vpc.reset_mock()
        self.cleaner.blockers.return_value = {"network_interfaces": [{"id": "eni-blocker"}]}
        with self.assertRaisesRegex(ValueError, "Dependencies still present"):
            self.cleaner.cleanup("vpc-1")
        self.ec2.delete_vpc.assert_not_called()

    def test_permission_errors_are_not_retried_as_dependencies(self):
        self.ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-1", "Tags": [{"Key": "Prefix", "Value": "example"}]}]}
        for stage in ("allocated_addresses", "remove_connections", "remove_autoscaling",
                      "remove_instances", "remove_load_balancers", "remove_efs_targets",
                      "remove_gateways_and_endpoints", "remove_interfaces", "release_addresses",
                      "remove_network"):
            setattr(self.cleaner, stage, Mock())
        self.cleaner.blockers = Mock(return_value={})
        self.ec2.delete_vpc.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, "DeleteVpc")
        with patch("environment_cleanup.time.sleep") as sleep:
            with self.assertRaises(ClientError):
                self.cleaner.cleanup("vpc-1")
        sleep.assert_not_called()
        self.ec2.delete_vpc.assert_called_once()

    def test_reassigned_elastic_ips_are_not_released(self):
        self.ec2.describe_addresses.return_value = {"Addresses": [
            {"AllocationId": "eip-owned"},
            {"AllocationId": "eip-reassigned", "NetworkInterfaceId": "eni-other"},
            {"AllocationId": "eip-unselected"}]}
        self.ec2.release_address.return_value = {}
        self.cleaner.release_addresses({"eip-owned", "eip-reassigned"})
        self.ec2.release_address.assert_called_once_with(AllocationId="eip-owned")

    @patch("environment_cleanup.configure_logging")
    @patch("environment_cleanup.VpcCleanup")
    @patch("environment_cleanup.boto3.Session")
    def test_report_and_account_gate_never_delete(self, session, cleaner, configure):
        session.return_value.client.return_value.get_caller_identity.return_value = {"Account": "123"}
        session.return_value.client.return_value.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "us-east-2"}]}
        cleaner.return_value.discover.return_value = [{"VpcId": "vpc-1"}]
        cleaner.return_value.blockers.return_value = {}
        cleaner.return_value.scan_extras.return_value = []
        with patch("environment_cleanup.sys.stdout"):
            self.assertEqual(cleanup.main(
                ["--region", "us-east-2", "--prefix", "example", "--skip-global"]), 0)
        cleaner.return_value.cleanup.assert_not_called()
        self.assertEqual(cleaner.call_args.args[1], "us-east-2")
        cleaner.reset_mock()
        with patch("environment_cleanup.sys.stdout"):
            self.assertEqual(cleanup.main(["--prefix", "example", "--skip-global"]), 0)
        self.assertEqual([call.args[1] for call in cleaner.call_args_list], ["us-east-1", "us-east-2"])
        cleaner.return_value.cleanup.assert_not_called()
        self.assertEqual(cleanup.main(["--region", "us-east-2", "--prefix", "example",
                                      "--execute", "--confirm-account", "wrong"]), 1)
        cleaner.return_value.cleanup.assert_not_called()

    @patch("environment_cleanup.configure_logging")
    @patch("environment_cleanup.VpcCleanup")
    @patch("environment_cleanup.boto3.Session")
    def test_execution_requires_tty_and_preserves_partial_failure_report(self, session, cleaner, configure):
        session.return_value.client.return_value.get_caller_identity.return_value = {"Account": "123"}
        session.return_value.client.return_value.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-2"}]}
        cleaner.return_value.discover.return_value = []
        entry = {"type": "ebs", "id": "vol-1", "name": "example-data", "region": "us-east-2"}
        cleaner.return_value.scan_extras.return_value = [entry]
        args = ["--region", "us-east-2", "--prefix", "example", "--skip-global",
                "--execute", "--confirm-account", "123"]
        with patch("environment_cleanup.sys.stdin.isatty", return_value=False):
            self.assertEqual(cleanup.main(args), 1)
        cleaner.return_value.cleanup_extra.assert_not_called()
        cleaner.return_value.cleanup_extra.side_effect = ValueError("still attached")
        output = io.StringIO()
        with patch("environment_cleanup.sys.stdin.isatty", return_value=True), \
                patch("environment_cleanup.pick", return_value=[entry]), \
                patch("environment_cleanup.prompt", return_value="delete 123"), \
                patch("environment_cleanup.sys.stdout", output):
            self.assertEqual(cleanup.main(args), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["failed"][0]["error"], "still attached")
        self.assertEqual(result["deletion_submitted"], [])

    @patch("environment_cleanup.global_delete")
    @patch("environment_cleanup.prefix_cleanup.scan")
    @patch("environment_cleanup.configure_logging")
    @patch("environment_cleanup.VpcCleanup")
    @patch("environment_cleanup.boto3.Session")
    def test_declining_vpc_security_group_preserves_vpc_and_global_resources(
            self, session, cleaner, configure, scan_global, delete_global):
        session.return_value.client.return_value.get_caller_identity.return_value = {"Account": "123"}
        session.return_value.client.return_value.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-2"}]}
        cleaner.return_value.discover.return_value = [{"VpcId": "vpc-1"}]
        cleaner.return_value.blockers.return_value = {}
        cleaner.return_value.scan_extras.return_value = []
        cleaner.return_value.resources.return_value = [{"GroupName": "example-sg", "GroupId": "sg-1"}]
        scan_global.return_value = [{"type": "s3-bucket", "id": "example-data", "region": "us-east-2"}]
        with patch("environment_cleanup.sys.stdin.isatty", return_value=True), \
                patch("environment_cleanup.pick", side_effect=lambda entries, label: entries), \
                patch("environment_cleanup.prompt", side_effect=["delete 123", "n"]), \
                patch("environment_cleanup.sys.stdout", io.StringIO()) as output:
            self.assertEqual(cleanup.main(["--region", "us-east-2", "--prefix", "example",
                                          "--execute", "--confirm-account", "123"]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(len(result["skipped"]), 2)
        cleaner.return_value.cleanup.assert_not_called()
        delete_global.assert_not_called()


if __name__ == "__main__":
    unittest.main()
