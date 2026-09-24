from unittest.mock import MagicMock

from app.models import Severity
from app.scanner import s3
from tests.helpers import client_error, fake_session

FULL_BLOCK = {setting: True for setting in s3.BLOCK_SETTINGS}
NO_BLOCK = {setting: False for setting in s3.BLOCK_SETTINGS}
SSE_S3 = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]


# S3-001: public access

def test_public_bucket_policy_is_high():
    finding = s3.check_public_access("public-site", NO_BLOCK, {}, policy_is_public=True, public_acl_grantees=[])
    assert (finding.id, finding.severity) == ("S3-001", Severity.HIGH)
    assert finding.title == "Potentially risky public access"
    assert "appears to be publicly accessible" in finding.description


def test_public_acl_is_high():
    finding = s3.check_public_access("legacy", NO_BLOCK, {}, policy_is_public=False, public_acl_grantees=["AllUsers"])
    assert finding.severity == Severity.HIGH
    assert "AllUsers" in finding.description


def test_account_level_restriction_neutralises_public_policy():
    account_block = {**NO_BLOCK, "RestrictPublicBuckets": True}
    finding = s3.check_public_access("site", account_block, {}, policy_is_public=True, public_acl_grantees=[])
    assert finding.severity == Severity.LOW  # not public, but Block Public Access is only partly on


def test_private_bucket_with_account_block_passes():
    assert s3.check_public_access("private", FULL_BLOCK, {}, policy_is_public=False, public_acl_grantees=[]) is None


def test_private_bucket_with_bucket_block_passes():
    assert s3.check_public_access("private", {}, FULL_BLOCK, policy_is_public=False, public_acl_grantees=[]) is None


def test_unreadable_policy_status_is_info_not_high():
    finding = s3.check_public_access("b", NO_BLOCK, NO_BLOCK, policy_is_public=None, public_acl_grantees=[])
    assert finding.severity == Severity.INFO
    assert finding.evidence["status"] == "unable_to_determine"


def test_unreadable_policy_status_does_not_matter_when_fully_blocked():
    assert s3.check_public_access("b", FULL_BLOCK, None, policy_is_public=None, public_acl_grantees=None) is None


# S3-002: default encryption

def test_encrypted_bucket_passes():
    assert s3.check_encryption("b", SSE_S3) is None


def test_bucket_without_default_encryption_is_medium():
    finding = s3.check_encryption("b", [])
    assert (finding.id, finding.severity) == ("S3-002", Severity.MEDIUM)


def test_unreadable_encryption_is_info():
    assert s3.check_encryption("b", None).severity == Severity.INFO


# scan() with mocked S3 clients

def mocked_clients():
    client = MagicMock()
    client.list_buckets.return_value = {"Buckets": [{"Name": "public-site"}, {"Name": "private-data"}]}

    def get_public_access_block(Bucket):
        if Bucket == "public-site":
            raise client_error("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": FULL_BLOCK}

    def get_bucket_encryption(Bucket):
        if Bucket == "public-site":
            raise client_error("ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption")
        return {"ServerSideEncryptionConfiguration": {"Rules": SSE_S3}}

    client.get_public_access_block.side_effect = get_public_access_block
    client.get_bucket_policy_status.side_effect = lambda Bucket: {"PolicyStatus": {"IsPublic": Bucket == "public-site"}}
    client.get_bucket_acl.return_value = {
        "Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]
    }
    client.get_bucket_encryption.side_effect = get_bucket_encryption

    s3control = MagicMock()
    s3control.get_public_access_block.side_effect = client_error(
        "NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock"
    )
    return client, s3control


def test_scan_flags_only_the_public_unencrypted_bucket():
    client, s3control = mocked_clients()
    result = s3.scan(fake_session(s3=client, s3control=s3control), "123456789012")

    assert {(f.resource, f.id, f.severity) for f in result.findings} == {
        ("public-site", "S3-001", Severity.HIGH),
        ("public-site", "S3-002", Severity.MEDIUM),
    }
    assert result.resources_scanned == 2


def test_scan_reports_unknown_account_settings_when_denied():
    client, s3control = mocked_clients()
    s3control.get_public_access_block.side_effect = client_error("AccessDenied", "GetPublicAccessBlock")

    result = s3.scan(fake_session(s3=client, s3control=s3control), "123456789012")

    account_findings = [f for f in result.findings if f.resource == "account/123456789012"]
    assert [f.severity for f in account_findings] == [Severity.INFO]
