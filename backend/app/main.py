import logging

from botocore.exceptions import ClientError
from botocore.exceptions import ConnectionError as AWSConnectionError
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from app.models import ScanResult
from app.scanner.common import error_code
from app.scanner.scanner import CredentialsError, run_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloudguard")

app = FastAPI(
    title="CloudGuard AI",
    version="0.1.0",
    description="Read-only AWS security scanner using deterministic rules.",
)


class ScanRequest(BaseModel):
    region: str | None = Field(default=None, pattern=r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$", examples=["ca-central-1"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResult)
def scan(request: ScanRequest | None = None) -> ScanResult:
    region = request.region if request else None
    try:
        return run_scan(region)
    except CredentialsError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    except AWSConnectionError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Could not connect to AWS. Check network access and the region.") from exc
    except ClientError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"AWS API error: {error_code(exc)}") from exc
    except Exception as exc:
        logger.exception("Scan failed")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Unexpected error while running the scan.") from exc
