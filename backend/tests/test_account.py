from unittest.mock import MagicMock

from app.models import Severity
from app.scanner import account
from tests.helpers import client_error, fake_session

ROOT = "arn:aws:iam::123456789012:root"


def summary(summary_map):
    return [(f.id, f.severity) for f in account.evaluate_root(summary_map, ROOT)]


def test_root_mfa_enabled_passes():
    assert summary({"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}) == []


def test_root_mfa_disabled_is_critical():
    assert summary({"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}) == [("ACCOUNT-001", Severity.CRITICAL)]


def test_root_without_password_is_informational():
    assert summary({"AccountMFAEnabled": 0, "AccountPasswordPresent": 0}) == [("ACCOUNT-001", Severity.INFO)]


def test_missing_mfa_field_is_unable_to_determine():
    assert summary({}) == [("ACCOUNT-001", Severity.INFO)]


def test_root_access_keys_are_critical():
    assert summary({"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}) == [("ACCOUNT-002", Severity.CRITICAL)]


def test_scan_access_denied_does_not_assume_the_worst():
    client = MagicMock()
    client.get_account_summary.side_effect = client_error("AccessDenied", "GetAccountSummary")

    result = account.scan(fake_session(iam=client), "123456789012")

    assert [(f.id, f.severity) for f in result.findings] == [("ACCOUNT-001", Severity.INFO)]
