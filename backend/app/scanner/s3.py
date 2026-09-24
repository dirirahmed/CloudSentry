import boto3
from botocore.exceptions import ClientError

from app.config import BOTO_CONFIG
from app.models import Finding, ServiceScan, Severity
from app.scanner.common import error_code, is_access_denied, unable_to_determine

SERVICE = "S3"

BLOCK_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}


def effective_block(account_block: dict | None, bucket_block: dict | None) -> dict[str, bool]:
    """A setting is in effect if it is enabled at either the account or the bucket level."""
    return {
        setting: bool((account_block or {}).get(setting) or (bucket_block or {}).get(setting))
        for setting in BLOCK_SETTINGS
    }


def check_public_access(
    bucket: str,
    account_block: dict | None,
    bucket_block: dict | None,
    policy_is_public: bool | None,
    public_acl_grantees: list[str] | None,
) -> Finding | None:
    """S3-001. A None argument means the value could not be read (access denied)."""
    block = effective_block(account_block, bucket_block)
    exposures = []
    if policy_is_public and not block["RestrictPublicBuckets"]:
        exposures.append("bucket policy")
    if public_acl_grantees and not block["IgnorePublicAcls"]:
        exposures.append(f"ACL grants to {', '.join(public_acl_grantees)}")

    evidence = {
        "effective_block_public_access": block,
        "account_settings_known": account_block is not None,
        "policy_is_public": policy_is_public,
        "public_acl_grantees": public_acl_grantees,
    }

    if exposures:
        return Finding(
            id="S3-001",
            service=SERVICE,
            title="Potentially risky public access",
            severity=Severity.HIGH,
            resource=bucket,
            description=f"Bucket '{bucket}' appears to be publicly accessible through its {' and '.join(exposures)}. "
            "Public access is sometimes intentional (for example, public website assets), but anything in the "
            "bucket may be readable by anyone on the internet.",
            evidence=evidence,
            recommendation="Confirm the bucket is meant to be public. If not, enable S3 Block Public Access and remove "
            "the public policy statements or ACL grants. For public content, consider CloudFront with Origin "
            "Access Control instead of a public bucket.",
        )
    fully_blocked = all(block.values())
    unknown = (
        (policy_is_public is None and not block["RestrictPublicBuckets"])
        or (public_acl_grantees is None and not block["IgnorePublicAcls"])
        or (bucket_block is None and not fully_blocked)
    )
    if unknown:
        return unable_to_determine(
            "S3-001", SERVICE, "Unable to determine public access", bucket,
            "access denied reading Block Public Access, policy status, or ACL",
        )
    if account_block is not None and not fully_blocked:
        return Finding(
            id="S3-001",
            service=SERVICE,
            title="S3 Block Public Access not fully enabled",
            severity=Severity.LOW,
            resource=bucket,
            description=f"Bucket '{bucket}' does not appear to be public, but Block Public Access is not fully "
            "enabled at the bucket or account level, so a future policy or ACL change could make it public.",
            evidence=evidence,
            recommendation="Enable all four Block Public Access settings at the account level (or on this bucket) "
            "unless public access is required.",
        )
    return None


def check_encryption(bucket: str, rules: list | None) -> Finding | None:
    """S3-002. rules is None when the configuration could not be read."""
    if rules is None:
        return unable_to_determine(
            "S3-002", SERVICE, "Unable to determine default encryption", bucket,
            "access denied for s3:GetEncryptionConfiguration",
        )
    if rules:
        return None
    return Finding(
        id="S3-002",
        service=SERVICE,
        title="Default encryption not configured",
        severity=Severity.MEDIUM,
        resource=bucket,
        description=f"No default server-side encryption configuration was returned for bucket '{bucket}'. "
        "Objects uploaded without an explicit encryption header may not be encrypted at rest.",
        evidence={"encryption_rules": []},
        recommendation="Enable default encryption (SSE-S3, or SSE-KMS if you need key-level access control and audit).",
    )


def _read(call, missing_code: str | None = None, **kwargs) -> dict | None:
    """Returns the response, {} if the configuration does not exist, or None if access is denied."""
    try:
        return call(**kwargs)
    except ClientError as exc:
        if missing_code and error_code(exc) == missing_code:
            return {}
        if is_access_denied(exc):
            return None
        raise


def _bucket_findings(client, bucket: str, account_block: dict | None) -> list[Finding]:
    pab = _read(client.get_public_access_block, "NoSuchPublicAccessBlockConfiguration", Bucket=bucket)
    status = _read(client.get_bucket_policy_status, "NoSuchBucketPolicy", Bucket=bucket)
    acl = _read(client.get_bucket_acl, Bucket=bucket)
    encryption = _read(client.get_bucket_encryption, "ServerSideEncryptionConfigurationNotFoundError", Bucket=bucket)

    bucket_block = None if pab is None else pab.get("PublicAccessBlockConfiguration", {})
    policy_is_public = None if status is None else status.get("PolicyStatus", {}).get("IsPublic", False)
    grantees = None if acl is None else sorted(
        {
            PUBLIC_GRANTEES[uri]
            for grant in acl.get("Grants", [])
            if (uri := grant.get("Grantee", {}).get("URI")) in PUBLIC_GRANTEES
        }
    )
    rules = None if encryption is None else encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

    results = (
        check_public_access(bucket, account_block, bucket_block, policy_is_public, grantees),
        check_encryption(bucket, rules),
    )
    return [f for f in results if f]


def scan(session: boto3.Session, account_id: str) -> ServiceScan:
    client = session.client("s3", config=BOTO_CONFIG)
    s3control = session.client("s3control", config=BOTO_CONFIG)

    response = _read(s3control.get_public_access_block, "NoSuchPublicAccessBlockConfiguration", AccountId=account_id)
    account_block = None if response is None else response.get("PublicAccessBlockConfiguration", {})

    findings = []
    if account_block is None:
        findings.append(
            unable_to_determine(
                "S3-001", SERVICE, "Unable to read account-level Block Public Access", f"account/{account_id}",
                "access denied for s3:GetAccountPublicAccessBlock",
            )
        )

    buckets = [b["Name"] for b in client.list_buckets().get("Buckets", [])]
    for bucket in buckets:
        try:
            findings += _bucket_findings(client, bucket, account_block)
        except ClientError as exc:
            findings.append(
                unable_to_determine("S3-001", SERVICE, "Unable to scan bucket", bucket, f"AWS returned {error_code(exc)}")
            )
    return ServiceScan(findings=findings, resources_scanned=len(buckets))
