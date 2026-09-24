from unittest.mock import MagicMock

import pytest
from botocore.exceptions import NoCredentialsError

from app.models import Finding, ServiceScan, Severity
from app.scanner import scanner
from tests.helpers import client_error, fake_session

FINDING = Finding(
    id="EC2-001", service="EC2", title="SSH exposed to the internet", severity=Severity.HIGH,
    resource="sg-1", description="d", recommendation="r",
)


def test_failing_scanners_do_not_stop_the_scan(monkeypatch):
    def ok(session, account_id):
        return ServiceScan(findings=[FINDING], resources_scanned=2)

    def denied(session, account_id):
        raise client_error("AccessDenied", "DescribeTrails")

    def broken(session, account_id):
        raise RuntimeError("internal detail that should not leak")

    monkeypatch.setattr(scanner, "SCANNERS", {"EC2": ok, "CloudTrail": denied, "S3": broken})
    result = scanner.scan_account(fake_session(region="ca-central-1"), "123456789012")

    assert result.account_id == "123456789012"
    assert result.region == "ca-central-1"
    assert result.findings_count == 1
    assert result.resources_scanned == 2
    assert [(e.service, e.code) for e in result.errors] == [("CloudTrail", "AccessDenied"), ("S3", "ScannerError")]
    assert "DescribeTrails" in result.errors[0].message
    assert "internal detail" not in result.model_dump_json()


def test_connect_returns_account_id(monkeypatch):
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn", "UserId": "id"}
    monkeypatch.setattr(scanner, "create_session", lambda region: fake_session(sts=sts))

    _, account_id = scanner.connect()
    assert account_id == "123456789012"


def test_missing_credentials_raise_credentials_error(monkeypatch):
    sts = MagicMock()
    sts.get_caller_identity.side_effect = NoCredentialsError()
    monkeypatch.setattr(scanner, "create_session", lambda region: fake_session(sts=sts))

    with pytest.raises(scanner.CredentialsError, match="No AWS credentials"):
        scanner.connect()


def test_invalid_credentials_raise_credentials_error(monkeypatch):
    sts = MagicMock()
    sts.get_caller_identity.side_effect = client_error("InvalidClientTokenId", "GetCallerIdentity")
    monkeypatch.setattr(scanner, "create_session", lambda region: fake_session(sts=sts))

    with pytest.raises(scanner.CredentialsError, match="invalid or expired"):
        scanner.connect()


def test_every_service_has_a_scanner():
    assert set(scanner.SCANNERS) == {"IAM", "S3", "EC2", "CloudTrail", "Account"}
