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
    @patch("aws_cleanup.scan_region")
    def test_region_failure_prevents_all_deletions(self, scan_region, scan_users, scan_lbs):
        item = cleanup.candidate("ebs", "vol-1", "region-a", "unattached")
        ec2 = Mock()
        ec2.describe_regions.return_value = {"Regions": [{"RegionName": "region-a"}, {"RegionName": "region-b"}]}
        sts = Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name="region-a")
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock()}[name]
        scan_region.side_effect = [[item], ValueError("region unavailable")]
        with self.assertRaisesRegex(ValueError, "region unavailable"):
            cleanup.run(session, [item["selection"]], "123456789012", NOW)
        ec2.delete_volume.assert_not_called()

    @patch("aws_cleanup.scan_load_balancers", return_value=[])
    @patch("aws_cleanup.scan_users", return_value=([], []))
    @patch("aws_cleanup.scan_region")
    def test_report_and_recheck_before_deletion(self, scan_region, scan_users, scan_lbs):
        item = cleanup.candidate("ebs", "vol-1", "us-east-1", "unattached")
        ec2 = Mock()
        ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        sts = Mock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda name, **kwargs: {"ec2": ec2, "sts": sts, "iam": Mock()}[name]
        scan_region.return_value = [item]
        result = cleanup.run(session, [], None, NOW)
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

    def test_iam_delete_does_not_remove_dependencies(self):
        iam = Mock()
        session = Mock()
        session.client.return_value = iam
        cleanup.delete_candidate(session, cleanup.candidate("iam-user", "user", "global", "inactive"))
        iam.delete_user.assert_called_once_with(UserName="user")
        self.assertEqual(iam.method_calls, [unittest.mock.call.delete_user(UserName="user")])


if __name__ == "__main__":
    unittest.main()
