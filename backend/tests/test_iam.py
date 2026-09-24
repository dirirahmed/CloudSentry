import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from urllib.parse import quote

from app.models import Severity
from app.scanner import iam
from tests.helpers import client_error, fake_session

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
USER_ARN = "arn:aws:iam::123456789012:user/alice"
BOT_ARN = "arn:aws:iam::123456789012:user/ci-bot"
POLICY_ARN = "arn:aws:iam::123456789012:policy/Example"


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def summary(findings):
    return [(f.id, f.severity) for f in findings]


# IAM-001 / IAM-002: policy analysis

def test_wildcard_admin_policy_is_critical():
    findings = iam.analyze_policy(policy(allow("*")), POLICY_ARN)
    assert summary(findings) == [("IAM-001", Severity.CRITICAL)]
    assert findings[0].title == "Policy grants full administrative access"


def test_wildcard_admin_policy_with_condition_is_high():
    condition = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
    findings = iam.analyze_policy(policy(allow("*", Condition=condition)), POLICY_ARN)
    assert summary(findings) == [("IAM-001", Severity.HIGH)]


def test_privileged_service_wildcard_is_high():
    assert summary(iam.analyze_policy(policy(allow("iam:*")), POLICY_ARN)) == [("IAM-001", Severity.HIGH)]


def test_other_service_wildcard_is_medium():
    assert summary(iam.analyze_policy(policy(allow("s3:*")), POLICY_ARN)) == [("IAM-001", Severity.MEDIUM)]


def test_service_wildcard_scoped_to_a_resource_is_not_flagged():
    doc = policy(allow("s3:*", "arn:aws:s3:::app-uploads/*"))
    assert iam.analyze_policy(doc, POLICY_ARN) == []


def test_restricted_policy_has_no_findings():
    doc = policy(
        allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::app-uploads/*"),
        allow("logs:PutLogEvents", "arn:aws:logs:ca-central-1:123456789012:log-group:/app/*"),
    )
    assert iam.analyze_policy(doc, POLICY_ARN) == []


def test_sensitive_action_on_all_resources():
    findings = iam.analyze_policy(policy(allow("iam:PassRole")), POLICY_ARN)
    assert summary(findings) == [("IAM-002", Severity.HIGH)]


def test_lower_risk_sensitive_action_is_medium():
    assert summary(iam.analyze_policy(policy(allow("s3:GetObject")), POLICY_ARN)) == [("IAM-002", Severity.MEDIUM)]


def test_sensitive_action_pattern_is_matched_case_insensitively():
    findings = iam.analyze_policy(policy(allow("iam:put*")), POLICY_ARN)
    assert summary(findings) == [("IAM-002", Severity.HIGH)]
    assert "iam:PutRolePolicy" in findings[0].evidence["statements"][0]["matched_actions"]


def test_allow_with_not_action_is_flagged():
    doc = policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert summary(iam.analyze_policy(doc, POLICY_ARN)) == [("IAM-001", Severity.HIGH)]


def test_deny_statements_are_ignored():
    doc = policy({"Effect": "Deny", "Action": "*", "Resource": "*"})
    assert iam.analyze_policy(doc, POLICY_ARN) == []


def test_url_encoded_document_is_parsed():
    encoded = quote(json.dumps(policy(allow("*"))))
    assert summary(iam.analyze_policy(encoded, POLICY_ARN)) == [("IAM-001", Severity.CRITICAL)]


# IAM-003: MFA

def test_console_user_without_mfa_is_flagged():
    finding = iam.check_user_mfa("alice", USER_ARN, has_console_access=True, has_mfa=False)
    assert finding.id == "IAM-003"
    assert finding.severity == Severity.HIGH


def test_console_user_with_mfa_passes():
    assert iam.check_user_mfa("alice", USER_ARN, has_console_access=True, has_mfa=True) is None


def test_api_only_user_does_not_need_mfa():
    assert iam.check_user_mfa("ci-bot", BOT_ARN, has_console_access=False, has_mfa=False) is None


# IAM-004: access keys

def check_key(status="Active", created_days_ago=400, last_used_days_ago=None):
    last_used = NOW - timedelta(days=last_used_days_ago) if last_used_days_ago is not None else None
    return iam.check_access_key(
        "ci-bot", BOT_ARN, "AKIAIOSFODNN7EXAMPLE", status,
        NOW - timedelta(days=created_days_ago), last_used, NOW, max_idle_days=90,
    )


def test_active_key_unused_for_a_long_time_is_medium():
    finding = check_key(last_used_days_ago=200)
    assert (finding.id, finding.severity) == ("IAM-004", Severity.MEDIUM)
    assert finding.evidence["idle_days"] == 200


def test_recently_used_key_passes():
    assert check_key(last_used_days_ago=5) is None


def test_new_key_that_was_never_used_passes():
    assert check_key(created_days_ago=10) is None


def test_old_key_that_was_never_used_is_flagged():
    finding = check_key(created_days_ago=120)
    assert finding.severity == Severity.MEDIUM
    assert "never been used" in finding.description


def test_deactivated_key_is_low():
    assert check_key(status="Inactive", last_used_days_ago=200).severity == Severity.LOW


def test_access_key_id_is_not_exposed():
    assert "AKIAIOSFODNN7EXAMPLE" not in check_key(last_used_days_ago=200).model_dump_json()


# scan() with a mocked IAM client

def mocked_iam_client():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {
            "UserDetailList": [
                {"UserName": "alice", "Arn": USER_ARN,
                 "UserPolicyList": [{"PolicyName": "inline-admin", "PolicyDocument": policy(allow("*"))}]},
                {"UserName": "ci-bot", "Arn": BOT_ARN, "UserPolicyList": []},
            ],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [
                {"PolicyName": "ReadReports", "Arn": POLICY_ARN, "AttachmentCount": 1,
                 "PolicyVersionList": [
                     {"Document": policy(allow("s3:GetObject", "arn:aws:s3:::reports/*")), "IsDefaultVersion": True},
                     {"Document": policy(allow("*")), "IsDefaultVersion": False},
                 ]},
            ],
        }
    ]

    def get_login_profile(UserName):
        if UserName == "alice":
            return {"LoginProfile": {"UserName": "alice"}}
        raise client_error("NoSuchEntity", "GetLoginProfile")

    client.get_login_profile.side_effect = get_login_profile
    client.list_mfa_devices.return_value = {"MFADevices": []}
    client.list_access_keys.side_effect = lambda UserName: {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIAEXAMPLEKEY000001", "Status": "Active", "CreateDate": NOW - timedelta(days=300)}
        ] if UserName == "ci-bot" else []
    }
    client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}
    return client


def test_scan_combines_policy_mfa_and_key_checks():
    client = mocked_iam_client()
    result = iam.scan(fake_session(iam=client), "123456789012", now=NOW)

    found = {(f.id, f.resource.split(" ")[0], f.severity) for f in result.findings}
    assert found == {
        ("IAM-001", USER_ARN, Severity.CRITICAL),  # inline admin policy
        ("IAM-003", USER_ARN, Severity.HIGH),      # console user without MFA
        ("IAM-004", BOT_ARN, Severity.MEDIUM),     # old key, never used
    }
    assert result.resources_scanned == 3
    client.get_paginator.return_value.paginate.assert_called_once_with(
        Filter=["User", "Group", "Role", "LocalManagedPolicy"]
    )


def test_scan_reports_unable_to_determine_when_user_checks_are_denied():
    client = mocked_iam_client()
    client.list_mfa_devices.side_effect = client_error("AccessDenied", "ListMFADevices")

    result = iam.scan(fake_session(iam=client), "123456789012", now=NOW)

    info = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info) == 1
    assert info[0].evidence["status"] == "unable_to_determine"
    assert any(f.id == "IAM-001" for f in result.findings)
