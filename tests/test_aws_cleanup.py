import logging
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import aws_cleanup as cleanup


NOW = datetime(2026, 11, 21, tzinfo=timezone.utc)


class Paginator:
    def __init__(self, response):
        self.response = response

    def paginate(self, **kwargs):
        return iter(self.response(kwargs))


class Client:
    def __init__(self, operations, **methods):
        self.operations = operations
        for name, value in methods.items():
            setattr(self, name, value)

    def get_paginator(self, operation):
        return Paginator(self.operations[operation])


def page(key, items):
    return lambda kwargs: [{key: items}]


class CleanupTests(unittest.TestCase):
    @patch("aws_cleanup.scan_load_balancers", return_value=[])
    @patch("aws_cleanup.scan_users", return_value=([], []))
    @patch("aws_cleanup.scan_file_systems", return_value=[])
    @patch("aws_cleanup.scan_security_groups_and_keys", return_value=[])
    @patch("aws_cleanup.scan_region", return_value=[])
    def test_explicit_region_limits_scan_without_default_region(
            self, scan_region, scan_keys, scan_efs, scan_users, scan_lbs):
        ec2 = Mock()
        ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "us-east-2"}]
        }
        sts = Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name=None)
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock(),
                                                              "efs": Mock()}[name]

        result = cleanup.run(session, [], None, NOW, region="us-east-2")

        self.assertEqual(result["regions"], ["us-east-2"])
        session.client.assert_any_call("sts", region_name="us-east-2")
        session.client.assert_any_call("ec2", region_name="us-east-2")
        scan_region.assert_called_once_with(ec2, "us-east-2")
        scan_keys.assert_called_once_with(ec2, "us-east-2")
        scan_efs.assert_called_once()
        scan_lbs.assert_called_once()

    def test_log_formatter_colors_console_only(self):
        record = logging.LogRecord("aws_cleanup", logging.INFO, "", 0, "scan complete", (), None)
        colored = cleanup.ConsoleFormatter(color=True).format(record)
        plain = cleanup.ConsoleFormatter(color=False).format(record)
        self.assertIn("\033[36m", colored)
        self.assertTrue(colored.endswith("\033[0m"))
        self.assertNotIn("\033[", plain)
        self.assertIn("INFO", plain)
        record.event = "success"
        self.assertIn("\033[32m", cleanup.ConsoleFormatter(color=True).format(record))

    def test_calendar_month_cutoff(self):
        self.assertEqual(cleanup.months_ago(datetime(2024, 11, 30, tzinfo=timezone.utc), 9),
                         datetime(2024, 2, 29, tzinfo=timezone.utc))

    def test_region_candidates_filter_associations_and_routes(self):
        ec2 = Client({
            "describe_route_tables": page("RouteTables", [{"Routes": [{"NatGatewayId": "nat-used"}]}]),
            "describe_nat_gateways": page("NatGateways", [
                {"NatGatewayId": "nat-used", "State": "available"},
                {"NatGatewayId": "nat-free", "State": "available"},
                {"NatGatewayId": "nat-pending", "State": "pending"}]),
            "describe_internet_gateways": page("InternetGateways", [
                {"InternetGatewayId": "igw-free", "Attachments": []},
                {"InternetGatewayId": "igw-used", "Attachments": [{"VpcId": "vpc-1"}]}]),
            "describe_volumes": page("Volumes", [
                {"VolumeId": "vol-free", "State": "available", "Attachments": [], "Size": 5},
                {"VolumeId": "vol-used", "State": "in-use", "Attachments": [{}], "Size": 5}]),
        }, describe_addresses=lambda: {"Addresses": [
            {"AllocationId": "eipalloc-free", "Domain": "vpc", "PublicIp": "192.0.2.1"},
            {"AllocationId": "eipalloc-used", "Domain": "vpc", "PublicIp": "192.0.2.2",
             "NetworkInterfaceId": "eni-1"},
            {"AllocationId": "eipalloc-service", "Domain": "vpc", "PublicIp": "192.0.2.3",
             "ServiceManaged": "service"}]})
        ids = {x["id"] for x in cleanup.scan_region(ec2, "us-east-1")}
        self.assertEqual(ids, {"eipalloc-free", "nat-free", "igw-free", "vol-free"})

    def test_iam_recent_activity_and_unknown_credential_types(self):
        old = datetime(2024, 1, 1, tzinfo=timezone.utc)
        recent = datetime(2026, 8, 1, tzinfo=timezone.utc)
        users = [{"UserName": name, "CreateDate": old} for name in
                 ("old", "active", "new-key", "unknown")]
        iam = Client({
            "list_users": page("Users", users),
            "list_signing_certificates": lambda k: [{"Certificates": [{}] if k["UserName"] == "unknown" else []}],
            "list_ssh_public_keys": page("SSHPublicKeys", []),
            "list_access_keys": lambda k: [{"AccessKeyMetadata": [
                {"AccessKeyId": k["UserName"], "CreateDate": recent if k["UserName"] == "new-key" else old}]}],
        }, list_service_specific_credentials=lambda **k: {"ServiceSpecificCredentials": []},
            get_access_key_last_used=lambda AccessKeyId: {"AccessKeyLastUsed":
                {"LastUsedDate": recent} if AccessKeyId == "active" else {}})
        found, excluded = cleanup.scan_users(iam, NOW)
        self.assertEqual([x["id"] for x in found], ["old"])
        self.assertEqual([x["user"] for x in excluded], ["unknown"])

    def test_load_balancers_and_target_groups(self):
        elbv2 = Client({
            "describe_load_balancers": page("LoadBalancers", [
                {"LoadBalancerArn": "arn:lb-free", "LoadBalancerName": "free"},
                {"LoadBalancerArn": "arn:lb-used", "LoadBalancerName": "used"}]),
            "describe_listeners": lambda k: [{"Listeners": [] if k["LoadBalancerArn"] == "arn:lb-free" else [{}]}],
            "describe_target_groups": page("TargetGroups", [
                {"TargetGroupArn": "arn:tg-free", "TargetGroupName": "free", "LoadBalancerArns": []},
                {"TargetGroupArn": "arn:tg-used", "TargetGroupName": "used", "LoadBalancerArns": ["arn:lb-used"]}]),
        })
        elb = Client({"describe_load_balancers": page("LoadBalancerDescriptions", [
            {"LoadBalancerName": "classic-free", "ListenerDescriptions": []},
            {"LoadBalancerName": "classic-used", "ListenerDescriptions": [{}]}])})
        session = Mock()
        session.client.side_effect = lambda name, **kwargs: {"elbv2": elbv2, "elb": elb}[name]
        found = cleanup.scan_load_balancers(session, "us-east-1")
        self.assertEqual({x["id"] for x in found}, {"arn:lb-free", "arn:tg-free", "classic-free"})

    def test_security_groups_and_key_pairs(self):
        ec2 = Client({
            "describe_network_interfaces": page("NetworkInterfaces", [{"Groups": [{"GroupId": "sg-used"}]}]),
            "describe_security_groups": page("SecurityGroups", [
                {"GroupId": "sg-used", "GroupName": "used"},
                {"GroupId": "sg-free", "GroupName": "free"},
                {"GroupId": "sg-default", "GroupName": "default"}]),
            "describe_instances": page("Reservations", [
                {"Instances": [{"KeyName": "used"}, {}]}]),
        }, describe_key_pairs=lambda: {"KeyPairs": [{"KeyName": "used", "KeyPairId": "key-used"},
                                                    {"KeyName": "free", "KeyPairId": "key-free"}]})
        found = cleanup.scan_security_groups_and_keys(ec2, "us-east-1")
        self.assertEqual({(item["type"], item["id"]) for item in found},
                         {("sg", "sg-free"), ("key-pair", "key-free")})

    def test_efs_only_available_without_mount_targets(self):
        efs = Client({
            "describe_file_systems": page("FileSystems", [
                {"FileSystemId": "fs-free", "LifeCycleState": "available"},
                {"FileSystemId": "fs-used", "LifeCycleState": "available"},
                {"FileSystemId": "fs-creating", "LifeCycleState": "creating"}]),
            "describe_mount_targets": lambda k: [{"MountTargets": [{}] if k["FileSystemId"] == "fs-used" else []}],
        })
        self.assertEqual([x["id"] for x in cleanup.scan_file_systems(efs, "us-east-1")], ["fs-free"])

    def test_service_credentials_checks_truncated_responses(self):
        iam = Mock()
        iam.list_service_specific_credentials.side_effect = [
            {"ServiceSpecificCredentials": [], "IsTruncated": True, "Marker": "next"},
            {"ServiceSpecificCredentials": [{}], "IsTruncated": False},
        ]
        self.assertTrue(cleanup.has_service_credentials(iam, "user"))
        iam.list_service_specific_credentials.assert_called_with(UserName="user", Marker="next")

    @patch("aws_cleanup.scan_load_balancers", return_value=[])
    @patch("aws_cleanup.scan_users", return_value=([], []))
    @patch("aws_cleanup.scan_file_systems", return_value=[])
    @patch("aws_cleanup.scan_security_groups_and_keys", return_value=[])
    @patch("aws_cleanup.scan_region")
    def test_region_failure_prevents_all_deletions(self, scan_region, scan_keys, scan_efs, scan_users, scan_lbs):
        item = cleanup.candidate("ebs", "vol-1", "region-a", "unattached")
        ec2 = Mock()
        ec2.describe_regions.return_value = {"Regions": [{"RegionName": "region-a"}, {"RegionName": "region-b"}]}
        sts = Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name="region-a")
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock(), "efs": Mock()}[name]
        scan_region.side_effect = [[item], ValueError("region unavailable")]
        with self.assertRaisesRegex(ValueError, "region unavailable"):
            cleanup.run(session, [item["selection"]], "123456789012", NOW)
        ec2.delete_volume.assert_not_called()

    @patch("aws_cleanup.scan_load_balancers", return_value=[])
    @patch("aws_cleanup.scan_users", return_value=([], []))
    @patch("aws_cleanup.scan_file_systems", return_value=[])
    @patch("aws_cleanup.scan_security_groups_and_keys", return_value=[])
    @patch("aws_cleanup.scan_region")
    def test_report_and_recheck_before_deletion(self, scan_region, scan_keys, scan_efs, scan_users, scan_lbs):
        item = cleanup.candidate("ebs", "vol-1", "us-east-1", "unattached")
        ec2 = Mock()
        ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        sts = Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock(), "efs": Mock()}[name]
        scan_region.return_value = [item]
        with self.assertLogs("aws_cleanup", level="INFO") as captured:
            result = cleanup.run(session, [], None, NOW)
        logs = "\n".join(captured.output)
        self.assertIn("Scanning region us-east-1", logs)
        self.assertIn("Found candidate: type=ebs name=vol-1 region=us-east-1", logs)
        self.assertIn("Not found: eip in us-east-1", logs)
        self.assertEqual(result["candidates"], [item])
        ec2.delete_volume.assert_not_called()
        with self.assertRaises(ValueError):
            cleanup.run(session, [item["selection"]], "wrong", NOW)
        scan_region.side_effect = [[item], []]
        with self.assertRaisesRegex(ValueError, "changed before deletion"):
            cleanup.run(session, [item["selection"]], "123456789012", NOW)
        ec2.delete_volume.assert_not_called()
        scan_region.side_effect = [[item], [item]]
        result = cleanup.run(session, [item["selection"]], "123456789012", NOW)
        ec2.delete_volume.assert_called_once_with(VolumeId="vol-1")
        self.assertEqual(result["deletion_submitted"], [item["selection"]])

    @patch("aws_cleanup.scan_load_balancers", return_value=[])
    @patch("aws_cleanup.scan_users", return_value=([], []))
    @patch("aws_cleanup.scan_file_systems", return_value=[])
    @patch("aws_cleanup.scan_security_groups_and_keys")
    @patch("aws_cleanup.scan_region", return_value=[])
    def test_sensitive_deletions_require_individual_confirmation(
            self, scan_region, scan_keys, scan_efs, scan_users, scan_lbs):
        ec2, sts = Mock(), Mock()
        ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock(), "efs": Mock()}[name]
        for kind, identifier, method in (("sg", "sg-1", "delete_security_group"),
                                         ("key-pair", "key-1", "delete_key_pair")):
            with self.subTest(kind=kind):
                item = cleanup.candidate(kind, identifier, "us-east-1", "unused")
                scan_keys.return_value = [item]
                stdin = Mock()
                stdin.isatty.return_value = False
                with patch("aws_cleanup.sys.stdin", stdin):
                    with self.assertRaisesRegex(ValueError, "interactive terminal"):
                        cleanup.run(session, [item["selection"]], "123456789012", NOW)
                getattr(ec2, method).assert_not_called()
                stdin.isatty.return_value = True
                stdin.readline.return_value = "no\n"
                with patch("aws_cleanup.sys.stdin", stdin):
                    with self.assertRaisesRegex(ValueError, "not confirmed"):
                        cleanup.run(session, [item["selection"]], "123456789012", NOW)
                getattr(ec2, method).assert_not_called()
                stdin.readline.return_value = item["selection"] + "\n"
                scan_keys.side_effect = [[item], []]
                with patch("aws_cleanup.sys.stdin", stdin):
                    with self.assertRaisesRegex(ValueError, "changed before deletion"):
                        cleanup.run(session, [item["selection"]], "123456789012", NOW)
                getattr(ec2, method).assert_not_called()
                scan_keys.side_effect = None
                with patch("aws_cleanup.sys.stdin", stdin):
                    result = cleanup.run(session, [item["selection"]], "123456789012", NOW)
                self.assertEqual(result["deletion_submitted"], [item["selection"]])
                getattr(ec2, method).assert_called_once()

    def test_menu_ranges_and_ask_mode(self):
        self.assertEqual(cleanup.parse_ranges("3, 1-2,2", 5), [0, 1, 2])
        self.assertEqual(cleanup.parse_ranges("all", 3), [0, 1, 2])
        self.assertEqual(cleanup.parse_ranges("", 3), [])
        for bad in ("0", "4", "2-1", "x"):
            with self.assertRaises(ValueError):
                cleanup.parse_ranges(bad, 3)
        with patch("aws_cleanup.sys.stdin") as stdin, patch("aws_cleanup.sys.stderr"):
            stdin.readline.side_effect = ["ask\n", "y\n", "n\n", "q\n"]
            self.assertEqual(cleanup.pick(["a", "b", "c", "d"], str), ["a"])

    @patch("aws_cleanup.scan_load_balancers", return_value=[])
    @patch("aws_cleanup.scan_users", return_value=([], []))
    @patch("aws_cleanup.scan_file_systems", return_value=[])
    @patch("aws_cleanup.scan_security_groups_and_keys")
    @patch("aws_cleanup.scan_region")
    def test_bulk_filter_and_plan_file(self, scan_region, scan_keys, scan_efs, scan_users, scan_lbs):
        vol = cleanup.candidate("ebs", "vol-1", "us-east-1", "unattached")
        eip = cleanup.candidate("eip", "eipalloc-1", "us-east-1", "unassociated")
        sg = cleanup.candidate("sg", "sg-1", "us-east-1", "unused")
        scan_region.return_value = [vol, eip]
        scan_keys.return_value = [sg]
        ec2 = Mock()
        ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        sts = Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock(), "efs": Mock()}[name]

        with patch("aws_cleanup.sys.stdin") as stdin, patch("aws_cleanup.sys.stderr"):
            stdin.isatty.return_value = True
            stdin.readline.side_effect = ["delete 1\n"]
            result = cleanup.run(session, [], "123456789012", NOW, cleanup.filter_chooser({"ebs"}, set()))
            self.assertEqual(result["deletion_submitted"], [vol["selection"]])
            ec2.release_address.assert_not_called()

            stdin.readline.side_effect = ["delete 2\n", "n\n"]
            result = cleanup.run(session, [], "123456789012", NOW, cleanup.filter_chooser(set(), set()))
            ec2.delete_security_group.assert_not_called()
            self.assertEqual(result["deletion_submitted"], [vol["selection"], eip["selection"]])

            stdin.readline.side_effect = ["no\n"]
            with self.assertRaisesRegex(ValueError, "not confirmed"):
                cleanup.run(session, [], "123456789012", NOW, cleanup.filter_chooser({"ebs"}, set()))

            stdin.readline.side_effect = ["y\n"]
            result = cleanup.run(session, [], "123456789012", NOW, cleanup.filter_chooser({"sg"}, set()))
            self.assertEqual(result["deletion_submitted"], [sg["selection"]])

            stdin.isatty.return_value = False
            with self.assertRaisesRegex(ValueError, "interactive terminal"):
                cleanup.run(session, [], "123456789012", NOW, cleanup.filter_chooser(set(), set()))

        with tempfile.TemporaryDirectory() as tmp:
            plan = os.path.join(tmp, "plan.txt")
            cleanup.run(session, [], None, NOW, plan_path=plan)
            with open(plan) as handle:
                kept = [line for line in handle if not line.startswith(("ebs:", "sg:"))]
            with open(plan, "w") as handle:
                handle.writelines(kept)
            self.assertEqual(cleanup.read_plan(plan)([]), [eip["selection"]])

    def test_new_delete_api_calls(self):
        session = Mock()
        client = session.client.return_value
        for kind, identifier in (("sg", "sg-1"), ("key-pair", "key-1"), ("efs", "fs-1")):
            cleanup.delete_candidate(session, cleanup.candidate(kind, identifier, "us-east-1", "candidate"))
        client.delete_security_group.assert_called_once_with(GroupId="sg-1")
        client.delete_key_pair.assert_called_once_with(KeyPairId="key-1")
        client.delete_file_system.assert_called_once_with(FileSystemId="fs-1")

    def test_iam_delete_does_not_remove_dependencies(self):
        iam = Mock()
        session = Mock()
        session.client.return_value = iam
        cleanup.delete_candidate(session, cleanup.candidate("iam-user", "user", "global", "inactive"))
        iam.delete_user.assert_called_once_with(UserName="user")
        self.assertEqual(iam.method_calls, [unittest.mock.call.delete_user(UserName="user")])


if __name__ == "__main__":
    unittest.main()
