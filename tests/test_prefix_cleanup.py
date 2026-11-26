import unittest
from unittest.mock import MagicMock, patch

import prefix_cleanup as pc


class Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return iter(self.pages(kwargs))


def client(paged=None, **methods):
    mock = MagicMock()
    paged = paged or {}
    mock.get_paginator.side_effect = lambda op: Paginator(paged.get(op, lambda kw: [{}]))
    for name, value in methods.items():
        setattr(mock, name, value)
    return mock


def page(key, items):
    return lambda kwargs: [{key: items}]


class PrefixCleanupTests(unittest.TestCase):
    def test_s3_discovery_paginates_and_normalizes_legacy_eu_region(self):
        iam = client()
        route53 = client()
        s3 = client()
        s3.list_buckets.side_effect = [
            {"Buckets": [{"Name": "unrelated"}], "ContinuationToken": "next"},
            {"Buckets": [{"Name": "coepse-data"}]},
        ]
        s3.get_bucket_location.return_value = {"LocationConstraint": "EU"}
        session = MagicMock()
        session.client.side_effect = lambda name, **kwargs: {"iam": iam, "s3": s3, "route53": route53}[name]
        found = pc.scan(session, "coepse")
        self.assertEqual(found, [{"type": "s3-bucket", "id": "coepse-data", "region": "eu-west-1"}])
        s3.list_buckets.assert_any_call(ContinuationToken="next")

    def test_s3_versions_markers_and_uploads_are_cleaned_before_bucket(self):
        s3 = client({
            "list_object_versions": page("Versions", [{"Key": "data", "VersionId": "v1"}]),
            "list_multipart_uploads": page("Uploads", [{"Key": "upload", "UploadId": "u1"}]),
        })
        s3.delete_objects.return_value = {}
        pc.delete_bucket(s3, "coepse-data")
        s3.delete_objects.assert_called_once_with(
            Bucket="coepse-data", Delete={"Objects": [{"Key": "data", "VersionId": "v1"}], "Quiet": True})
        calls = [call[0] for call in s3.method_calls]
        self.assertLess(calls.index("delete_objects"), calls.index("delete_bucket"))
        self.assertLess(calls.index("abort_multipart_upload"), calls.index("delete_bucket"))

    def test_s3_partial_delete_errors_prevent_bucket_deletion(self):
        s3 = client({"list_object_versions": page("DeleteMarkers", [{"Key": "data", "VersionId": "v1"}])})
        s3.delete_objects.return_value = {"Errors": [{"Code": "AccessDenied", "Key": "data"}]}
        with self.assertRaisesRegex(ValueError, "AccessDenied"):
            pc.delete_bucket(s3, "coepse-data")
        s3.delete_bucket.assert_not_called()

    def test_token_match(self):
        for name in ("coepse", "coepse-csk-bastion-ssm", "ccf-restricted-coepse-s3-policy", "COEPSE_x",
                     "bucket-coepse"):
            self.assertTrue(pc.matches(name, "coepse"), name)
        for name in ("coepsex-role", "xcoepse", "mycoepse-bucket", "psecoe-csk"):
            self.assertFalse(pc.matches(name, "coepse"), name)

    def test_scan_selects_prefix_resources_only(self):
        iam = client({
            "list_users": page("Users", [{"UserName": "coepse-csk-ccf-awc-restricted"},
                                         {"UserName": "psecoe-csk-ccf-awc-restricted"}]),
            "list_instance_profiles": page("InstanceProfiles", [
                {"InstanceProfileName": "coepse-csk-bastion-ssm", "Roles": [{"RoleName": "coepse-csk-bastion-ssm"}]}]),
            "list_roles": page("Roles", [
                {"RoleName": "coepse-csk-bastion-ssm", "Path": "/"},
                {"RoleName": "AWSServiceRoleFor-coepse", "Path": "/aws-service-role/x/"}]),
            "list_policies": page("Policies", [
                {"PolicyName": "ccf-restricted-coepse-ec2-policy", "Arn": "arn:p1", "AttachmentCount": 1},
                {"PolicyName": "ccf-restricted-qbeast-ec2-policy", "Arn": "arn:p2"}]),
        })
        s3 = client(list_buckets=lambda: {"Buckets": [{"Name": "coepse-data"}, {"Name": "other"}]},
                    get_bucket_location=lambda Bucket: {"LocationConstraint": "us-east-2"})
        route53 = client({"list_hosted_zones": page("HostedZones", [
            {"Id": "/hostedzone/Z1", "Name": "coepse.example.com.", "Config": {"PrivateZone": False}},
            {"Id": "/hostedzone/Z2", "Name": "example.com.", "Config": {"PrivateZone": False}},
            {"Id": "/hostedzone/Z3", "Name": "a.coepse.example.com.", "Config": {"PrivateZone": False}},
            {"Id": "/hostedzone/Z4", "Name": "coepse-x.example.com.", "Config": {"PrivateZone": False}}])})
        session = MagicMock()
        session.client.side_effect = lambda name, **kw: {"iam": iam, "s3": s3, "route53": route53}[name]

        found = [(x["type"], x["id"]) for x in pc.scan(session, "coepse")]
        self.assertEqual(found, [
            ("iam-user", "coepse-csk-ccf-awc-restricted"),
            ("instance-profile", "coepse-csk-bastion-ssm"),
            ("iam-role", "coepse-csk-bastion-ssm"),
            ("iam-policy", "arn:p1"),
            ("s3-bucket", "coepse-data"),
            ("hosted-zone", "Z1"),
        ])

    def test_user_keys_deactivated_before_any_deletion(self):
        calls = []
        iam = client({"list_access_keys": page("AccessKeyMetadata", [{"AccessKeyId": "AK1"}, {"AccessKeyId": "AK2"}]),
                      "list_attached_user_policies": page("AttachedPolicies", [{"PolicyArn": "arn:p"}])})
        iam.list_service_specific_credentials.return_value = {}
        iam.get_user.return_value = {"User": {}}
        for name in ("update_access_key", "delete_access_key", "delete_login_profile",
                     "detach_user_policy", "delete_user"):
            getattr(iam, name).side_effect = lambda n=name, **kw: calls.append((n, kw.get("AccessKeyId")))
        pc.delete_user(iam, "coepse-user")
        names = [c[0] for c in calls]
        self.assertEqual(names[:2], ["update_access_key", "update_access_key"])
        self.assertEqual(names[-1], "delete_user")
        self.assertLess(names.index("detach_user_policy"), names.index("delete_user"))

    def test_deletion_gates(self):
        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": "123"}
        with self.assertRaisesRegex(ValueError, "at least 3"):
            pc.run(session, "c", None, False, None)
        with self.assertRaisesRegex(ValueError, "--confirm-account 123"):
            pc.run(session, "coepse", None, True, "999")
        with patch.object(pc, "scan", return_value=[{"type": "iam-user", "id": "coepse-u"}]), \
                patch.object(pc.sys.stdin, "isatty", return_value=False), \
                patch.object(pc, "delete") as delete:
            with self.assertRaisesRegex(ValueError, "interactive"):
                pc.run(session, "coepse", None, True, "123")
            delete.assert_not_called()
            report = pc.run(session, "coepse", None, False, None)
            self.assertEqual(report["deleted"], [])
            delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
