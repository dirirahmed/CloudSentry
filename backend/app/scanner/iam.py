import json
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError

from app.config import BOTO_CONFIG, UNUSED_ACCESS_KEY_DAYS
from app.models import Finding, ServiceScan, Severity
from app.scanner.common import error_code, is_access_denied, unable_to_determine

SERVICE = "IAM"

# "service:*" on these services on Resource "*" allows privilege escalation or credential access.
PRIVILEGED_SERVICES = {"iam", "sts", "kms", "organizations", "secretsmanager"}

# Individual actions that are risky when granted on Resource "*" (IAM-002).
SENSITIVE_ACTIONS: dict[str, Severity] = {
    "iam:PassRole": Severity.HIGH,
    "iam:CreatePolicyVersion": Severity.HIGH,
    "iam:SetDefaultPolicyVersion": Severity.HIGH,
    "iam:AttachUserPolicy": Severity.HIGH,
    "iam:AttachRolePolicy": Severity.HIGH,
    "iam:AttachGroupPolicy": Severity.HIGH,
    "iam:PutUserPolicy": Severity.HIGH,
    "iam:PutRolePolicy": Severity.HIGH,
    "iam:PutGroupPolicy": Severity.HIGH,
    "iam:CreateAccessKey": Severity.HIGH,
    "iam:CreateLoginProfile": Severity.HIGH,
    "iam:UpdateLoginProfile": Severity.HIGH,
    "iam:UpdateAssumeRolePolicy": Severity.HIGH,
    "secretsmanager:GetSecretValue": Severity.HIGH,
    "s3:PutBucketPolicy": Severity.HIGH,
    "cloudtrail:StopLogging": Severity.HIGH,
    "cloudtrail:DeleteTrail": Severity.HIGH,
    "kms:ScheduleKeyDeletion": Severity.HIGH,
    "sts:AssumeRole": Severity.MEDIUM,
    "kms:Decrypt": Severity.MEDIUM,
    "ssm:GetParameter": Severity.MEDIUM,
    "ssm:GetParameters": Severity.MEDIUM,
    "s3:GetObject": Severity.MEDIUM,
    "s3:DeleteBucket": Severity.MEDIUM,
    "ec2:TerminateInstances": Severity.MEDIUM,
    "lambda:UpdateFunctionCode": Severity.MEDIUM,
}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _load_document(document: Any) -> dict:
    # boto3 normally decodes policy documents; the raw API returns URL-encoded JSON.
    if isinstance(document, str):
        return json.loads(unquote(document))
    return document or {}


def _worst(severities) -> Severity:
    return min(severities, key=lambda s: s.rank)


def wildcard_severity(action: str, all_resources: bool, conditional: bool) -> Severity | None:
    """Severity for IAM-001, or None if the action is not a wildcard we report."""
    if action == "*":
        return Severity.CRITICAL if all_resources and not conditional else Severity.HIGH
    service, _, name = action.partition(":")
    if name == "*" and all_resources:
        return Severity.HIGH if service.lower() in PRIVILEGED_SERVICES else Severity.MEDIUM
    return None


def sensitive_matches(action: str) -> dict[str, Severity]:
    """Sensitive actions covered by an action pattern such as 'iam:Put*' (case-insensitive)."""
    return {
        name: severity
        for name, severity in SENSITIVE_ACTIONS.items()
        if fnmatchcase(name.lower(), action.lower())
    }


def analyze_policy(document: Any, resource: str, context: dict | None = None) -> list[Finding]:
    """Apply IAM-001 and IAM-002 to one policy document."""
    statements = _load_document(document).get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    wildcard: list[tuple[Severity, dict]] = []
    sensitive: list[tuple[Severity, dict]] = []

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        resources = _as_list(stmt.get("Resource"))
        all_resources = "*" in resources
        conditional = "Condition" in stmt

        if "NotAction" in stmt:
            # Allow + NotAction grants everything except the listed actions.
            if all_resources:
                detail = {"not_action": _as_list(stmt["NotAction"]), "resources": resources, "conditional": conditional}
                wildcard.append((Severity.HIGH, detail))
            continue

        for action in _as_list(stmt.get("Action")):
            detail = {"action": action, "resources": resources, "conditional": conditional}
            if severity := wildcard_severity(action, all_resources, conditional):
                wildcard.append((severity, detail))
            elif all_resources and (matches := sensitive_matches(action)):
                sensitive.append((_worst(matches.values()), {**detail, "matched_actions": sorted(matches)}))

    context = context or {}
    findings = []
    if wildcard:
        severity = _worst(s for s, _ in wildcard)
        full_admin = severity == Severity.CRITICAL
        findings.append(
            Finding(
                id="IAM-001",
                service=SERVICE,
                title="Policy grants full administrative access" if full_admin else "Policy grants wildcard permissions",
                severity=severity,
                resource=resource,
                description=(
                    "This policy allows every action on every resource with no conditions. "
                    "That is sometimes intentional for a small number of administrator or break-glass "
                    "identities, but it should be rare and deliberate."
                    if full_admin
                    else "This policy uses wildcard actions (such as 'service:*' or NotAction). Broad grants make it "
                    "hard to reason about what an identity can do and increase the impact if it is misused."
                ),
                evidence={**context, "statements": [d for _, d in wildcard]},
                recommendation="Scope the policy to the specific actions and resources the workload needs. "
                "IAM Access Analyzer can generate a least-privilege policy from CloudTrail activity.",
            )
        )
    if sensitive:
        findings.append(
            Finding(
                id="IAM-002",
                service=SERVICE,
                title="Sensitive actions allowed on all resources",
                severity=_worst(s for s, _ in sensitive),
                resource=resource,
                description="This policy allows sensitive actions on Resource '*'. Depending on the action, this can "
                "enable privilege escalation, reading secrets or data, or disabling security controls across "
                "the whole account. Whether it is appropriate depends on how the identity is used.",
                evidence={**context, "statements": [d for _, d in sensitive]},
                recommendation="Restrict these actions to specific resource ARNs and add conditions where possible "
                "(for example, limit iam:PassRole to named roles with the iam:PassedToService condition).",
            )
        )
    return findings


def check_user_mfa(user_name: str, user_arn: str, has_console_access: bool, has_mfa: bool) -> Finding | None:
    """IAM-003. Users without a console password (API-only) are not expected to have MFA."""
    if not has_console_access or has_mfa:
        return None
    return Finding(
        id="IAM-003",
        service=SERVICE,
        title="IAM user with console access has no MFA",
        severity=Severity.HIGH,
        resource=user_arn,
        description=f"User '{user_name}' can sign in to the AWS console with a password but has no MFA device. "
        "A leaked or guessed password alone would be enough to sign in.",
        evidence={"user_name": user_name, "console_access": True, "mfa_devices": 0},
        recommendation="Register an MFA device for this user, or remove the console password if the user only "
        "needs programmatic access.",
    )


def check_access_key(
    user_name: str,
    user_arn: str,
    key_id: str,
    status: str,
    created: datetime,
    last_used: datetime | None,
    now: datetime,
    max_idle_days: int = UNUSED_ACCESS_KEY_DAYS,
) -> Finding | None:
    """IAM-004. Flags keys idle for at least max_idle_days (since last use, or since creation if never used)."""
    idle_days = (now - (last_used or created)).days
    if idle_days < max_idle_days:
        return None

    active = status == "Active"
    usage = f"has not been used for {idle_days} days" if last_used else f"has never been used (created {idle_days} days ago)"
    return Finding(
        id="IAM-004",
        service=SERVICE,
        title="Unused active access key" if active else "Deactivated access key not deleted",
        severity=Severity.MEDIUM if active else Severity.LOW,
        resource=f"{user_arn} (access key ending {key_id[-4:]})",
        description=f"Access key ending {key_id[-4:]} for user '{user_name}' {usage}. "
        + (
            "An unused active key is a long-lived credential that adds risk without providing value. "
            "This does not mean the key has been compromised."
            if active
            else "The key is deactivated and cannot be used, but it could be reactivated."
        ),
        evidence={
            "user_name": user_name,
            "access_key_suffix": key_id[-4:],
            "status": status,
            "created": created.isoformat(),
            "last_used": last_used.isoformat() if last_used else None,
            "idle_days": idle_days,
            "threshold_days": max_idle_days,
        },
        recommendation=(
            "Deactivate and then delete the key if it is no longer needed. Prefer IAM roles with temporary "
            "credentials over long-lived access keys."
            if active
            else "Delete the key if it is no longer needed."
        ),
    )


def _authorization_details(client) -> dict[str, list]:
    keys = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
    merged: dict[str, list] = {key: [] for key in keys}
    paginator = client.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User", "Group", "Role", "LocalManagedPolicy"]):
        for key in keys:
            merged[key].extend(page.get(key, []))
    return merged


def _policy_findings(details: dict[str, list]) -> list[Finding]:
    findings = []
    for policy in details["Policies"]:
        document = next(
            (v["Document"] for v in policy.get("PolicyVersionList", []) if v.get("IsDefaultVersion")),
            None,
        )
        if document is not None:
            context = {
                "policy_name": policy["PolicyName"],
                "policy_type": "customer_managed",
                "attachment_count": policy.get("AttachmentCount", 0),
            }
            findings += analyze_policy(document, policy["Arn"], context)

    for list_key, policy_key in (
        ("UserDetailList", "UserPolicyList"),
        ("GroupDetailList", "GroupPolicyList"),
        ("RoleDetailList", "RolePolicyList"),
    ):
        for entity in details[list_key]:
            for inline in entity.get(policy_key, []):
                context = {"policy_name": inline["PolicyName"], "policy_type": "inline"}
                findings += analyze_policy(inline["PolicyDocument"], entity["Arn"], context)
    return findings


def _has_console_access(client, user_name: str) -> bool:
    try:
        client.get_login_profile(UserName=user_name)
        return True
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            return False
        raise


def _user_findings(client, user: dict, now: datetime) -> list[Finding]:
    name, arn = user["UserName"], user["Arn"]
    has_mfa = bool(client.list_mfa_devices(UserName=name)["MFADevices"])
    findings = [check_user_mfa(name, arn, _has_console_access(client, name), has_mfa)]

    for key in client.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        usage = client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
        findings.append(
            check_access_key(name, arn, key["AccessKeyId"], key["Status"], key["CreateDate"], usage.get("LastUsedDate"), now)
        )
    return [f for f in findings if f]


def scan(session: boto3.Session, account_id: str, now: datetime | None = None) -> ServiceScan:
    client = session.client("iam", config=BOTO_CONFIG)
    now = now or datetime.now(timezone.utc)
    details = _authorization_details(client)
    findings = _policy_findings(details)

    try:
        for user in details["UserDetailList"]:
            findings += _user_findings(client, user, now)
    except ClientError as exc:
        if not is_access_denied(exc):
            raise
        findings.append(
            unable_to_determine(
                "IAM-003",
                SERVICE,
                "Unable to evaluate IAM user MFA and access keys",
                f"arn:aws:iam::{account_id}:user/*",
                f"access denied for iam:{exc.operation_name}",
            )
        )

    resources = sum(len(details[k]) for k in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"))
    return ServiceScan(findings=findings, resources_scanned=resources)
