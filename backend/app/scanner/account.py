import boto3
from botocore.exceptions import ClientError

from app.config import BOTO_CONFIG
from app.models import Finding, ServiceScan, Severity
from app.scanner.common import is_access_denied, unable_to_determine

SERVICE = "Account"


def evaluate_root(summary: dict, resource: str) -> list[Finding]:
    """ACCOUNT-001 (root MFA) and ACCOUNT-002 (root access keys) from iam:GetAccountSummary."""
    findings = []
    mfa = summary.get("AccountMFAEnabled")
    password = summary.get("AccountPasswordPresent")  # not returned by every API version

    if mfa is None:
        findings.append(unable_to_determine("ACCOUNT-001", SERVICE, "Unable to determine root MFA status",
                                            resource, "AccountMFAEnabled was not returned"))
    elif mfa == 0 and password == 0:
        findings.append(Finding(
            id="ACCOUNT-001", service=SERVICE, title="Root user has no password", severity=Severity.INFO,
            resource=resource, evidence={"AccountMFAEnabled": 0, "AccountPasswordPresent": 0},
            description="The root user has no MFA device, but also has no console password (for example, when "
            "root access is centrally managed through AWS Organizations).",
            recommendation="No action needed if root credentials are intentionally removed.",
        ))
    elif mfa == 0:
        findings.append(Finding(
            id="ACCOUNT-001", service=SERVICE, title="Root user MFA is not enabled", severity=Severity.CRITICAL,
            resource=resource, evidence={"AccountMFAEnabled": 0},
            description="AWS reports that the root user has no MFA device. The root user has unrestricted access "
            "to the account and cannot be limited by IAM policies. If root credentials are centrally managed "
            "through AWS Organizations, confirm whether this still applies.",
            recommendation="Enable MFA on the root user (a hardware key or passkey is preferred) and avoid using "
            "the root user for day-to-day work.",
        ))

    if summary.get("AccountAccessKeysPresent") == 1:
        findings.append(Finding(
            id="ACCOUNT-002", service=SERVICE, title="Root user has access keys", severity=Severity.CRITICAL,
            resource=resource, evidence={"AccountAccessKeysPresent": 1},
            description="The root user has at least one access key. Root access keys give unrestricted, long-lived "
            "programmatic access to the account.",
            recommendation="Delete the root access keys and use IAM roles or IAM Identity Center instead.",
        ))
    return findings


def scan(session: boto3.Session, account_id: str) -> ServiceScan:
    client = session.client("iam", config=BOTO_CONFIG)
    resource = f"arn:aws:iam::{account_id}:root"
    try:
        summary = client.get_account_summary()["SummaryMap"]
    except ClientError as exc:
        if not is_access_denied(exc):
            raise
        finding = unable_to_determine("ACCOUNT-001", SERVICE, "Unable to determine root MFA status", resource,
                                      "access denied for iam:GetAccountSummary")
        return ServiceScan(findings=[finding], resources_scanned=1)
    return ServiceScan(findings=evaluate_root(summary, resource), resources_scanned=1)
