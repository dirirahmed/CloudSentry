import logging
from collections.abc import Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from botocore.exceptions import ConnectionError as AWSConnectionError
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ProfileNotFound

from app.config import AWS_REGION, BOTO_CONFIG, FALLBACK_REGION
from app.models import Finding, ScanResult, ServiceError, ServiceScan
from app.scanner import account, cloudtrail, ec2, iam, s3
from app.scanner.common import error_code, is_access_denied

logger = logging.getLogger(__name__)

ServiceScanner = Callable[[boto3.Session, str], ServiceScan]

SCANNERS: dict[str, ServiceScanner] = {
    "IAM": iam.scan,
    "S3": s3.scan,
    "EC2": ec2.scan,
    "CloudTrail": cloudtrail.scan,
    "Account": account.scan,
}

INVALID_CREDENTIAL_CODES = {
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "ExpiredToken",
    "ExpiredTokenException",
    "UnrecognizedClientException",
}


class CredentialsError(Exception):
    """AWS credentials are missing, invalid or expired. The message is safe to return to clients."""


def create_session(region: str | None = None) -> boto3.Session:
    session = boto3.Session(region_name=region or AWS_REGION)
    if session.region_name is None:
        session = boto3.Session(region_name=FALLBACK_REGION)
    return session


def connect(region: str | None = None) -> tuple[boto3.Session, str]:
    """Create a session and confirm the credentials work. Returns (session, account_id)."""
    try:
        session = create_session(region)
        identity = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
    except AWSConnectionError:
        raise
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsError(
            "No AWS credentials found. Configure them with environment variables, AWS_PROFILE, or `aws configure`."
        ) from exc
    except ProfileNotFound as exc:
        raise CredentialsError("The configured AWS profile was not found.") from exc
    except BotoCoreError as exc:
        raise CredentialsError(
            "AWS credentials could not be loaded. If you use IAM Identity Center, run `aws sso login`."
        ) from exc
    except ClientError as exc:
        if error_code(exc) in INVALID_CREDENTIAL_CODES:
            raise CredentialsError("AWS rejected the credentials. They may be invalid or expired.") from exc
        raise
    return session, identity["Account"]


def _service_error(service: str, exc: ClientError) -> ServiceError:
    code = error_code(exc)
    if is_access_denied(exc):
        message = f"Missing permission for {exc.operation_name}. See docs/iam-policy.json."
    else:
        message = f"AWS returned {code} for {exc.operation_name}."
    return ServiceError(service=service, code=code, message=message)


def scan_account(session: boto3.Session, account_id: str) -> ScanResult:
    """Run every service scanner. A failing scanner is reported in `errors` and does not stop the others."""
    findings: list[Finding] = []
    errors: list[ServiceError] = []
    resources = 0

    for service, scanner in SCANNERS.items():
        try:
            result = scanner(session, account_id)
        except ClientError as exc:
            errors.append(_service_error(service, exc))
        except AWSConnectionError:
            errors.append(ServiceError(service=service, code="EndpointUnavailable",
                                       message=f"Could not reach the {service} API in this region."))
        except Exception:
            logger.exception("%s scanner failed", service)
            errors.append(ServiceError(service=service, code="ScannerError",
                                       message="Unexpected scanner failure. See server logs for details."))
        else:
            findings += result.findings
            resources += result.resources_scanned

    return ScanResult.build(account_id, session.region_name, resources, findings, errors)


def run_scan(region: str | None = None) -> ScanResult:
    session, account_id = connect(region)
    return scan_account(session, account_id)
