import boto3
from botocore.exceptions import ClientError

from app.config import BOTO_CONFIG
from app.models import Finding, ServiceScan, Severity
from app.scanner.common import error_code, is_access_denied, unable_to_determine

SERVICE = "CloudTrail"
RECOMMENDATION = (
    "Create a multi-region trail (or use an AWS Organizations trail) that delivers logs to an S3 bucket "
    "with restricted access, and keep logging enabled."
)


def evaluate_trails(trails: list[dict], resource: str) -> list[Finding]:
    """CT-001. Each trail dict has 'name', 'multi_region' and 'is_logging' (None = unknown)."""
    evidence = {"trails": trails}

    if not trails:
        return [Finding(
            id="CT-001", service=SERVICE, title="No CloudTrail trail configured", severity=Severity.HIGH,
            resource=resource, evidence=evidence, recommendation=RECOMMENDATION,
            description="No trail covers this region. CloudTrail Event history still keeps 90 days of management "
            "events, but without a trail there is no long-term audit log for investigations.",
        )]

    logging = [t for t in trails if t["is_logging"]]
    if not logging:
        if any(t["is_logging"] is None for t in trails):
            return [unable_to_determine("CT-001", SERVICE, "Unable to determine CloudTrail logging status",
                                        resource, "trail status could not be read")]
        return [Finding(
            id="CT-001", service=SERVICE, title="CloudTrail trails exist but none are logging", severity=Severity.HIGH,
            resource=resource, evidence=evidence, recommendation=RECOMMENDATION,
            description="Trails are configured for this region, but logging is stopped on all of them.",
        )]

    if not any(t["multi_region"] for t in logging):
        return [Finding(
            id="CT-001", service=SERVICE, title="No multi-region CloudTrail trail is logging", severity=Severity.MEDIUM,
            resource=resource, evidence=evidence, recommendation=RECOMMENDATION,
            description="Logging is enabled, but only through single-region trails. Activity in other regions "
            "may not be recorded.",
        )]
    return []


def _is_logging(client, trail_arn: str) -> bool | None:
    try:
        return client.get_trail_status(Name=trail_arn)["IsLogging"]
    except ClientError as exc:
        if is_access_denied(exc) or error_code(exc) == "TrailNotFoundException":
            return None
        raise


def scan(session: boto3.Session, account_id: str) -> ServiceScan:
    client = session.client("cloudtrail", config=BOTO_CONFIG)
    resource = f"account/{account_id} ({session.region_name})"
    try:
        trail_list = client.describe_trails(includeShadowTrails=True)["trailList"]
    except ClientError as exc:
        if not is_access_denied(exc):
            raise
        finding = unable_to_determine("CT-001", SERVICE, "Unable to determine CloudTrail status", resource,
                                      "access denied for cloudtrail:DescribeTrails")
        return ServiceScan(findings=[finding])

    trails = [
        {
            "name": t["Name"],
            "home_region": t.get("HomeRegion"),
            "multi_region": t.get("IsMultiRegionTrail", False),
            "organization_trail": t.get("IsOrganizationTrail", False),
            "is_logging": _is_logging(client, t["TrailARN"]),
        }
        for t in trail_list
    ]
    return ServiceScan(findings=evaluate_trails(trails, resource), resources_scanned=len(trails))
