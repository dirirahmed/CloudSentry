from botocore.exceptions import ClientError

from app.models import Finding, Severity

ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthorizationError",
        "UnauthorizedAccess",
        "UnauthorizedOperation",
    }
)

PERMISSIONS_HINT = "Grant the read-only permissions in docs/iam-policy.json and run the scan again."


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "Unknown")


def is_access_denied(exc: ClientError) -> bool:
    return error_code(exc) in ACCESS_DENIED_CODES


def unable_to_determine(rule_id: str, service: str, title: str, resource: str, reason: str) -> Finding:
    """An INFO result for a check that ran but could not reach a conclusion."""
    return Finding(
        id=rule_id,
        service=service,
        title=title,
        severity=Severity.INFO,
        resource=resource,
        description=f"The scanner could not determine the result of this check ({reason}). "
        "This is not evidence of a problem.",
        evidence={"status": "unable_to_determine", "reason": reason},
        recommendation=PERMISSIONS_HINT,
    )
