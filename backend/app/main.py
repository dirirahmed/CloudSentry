import logging

from botocore.exceptions import ClientError
from botocore.exceptions import ConnectionError as AWSConnectionError
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from app.ai.analysis import explain_scan
from app.ai.bedrock import BedrockService
from app.config import BEDROCK_MODEL_ID, BEDROCK_REGION
from app.models import ScanResult
from app.scanner.common import error_code
from app.scanner.scanner import CredentialsError, run_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloudsentry")

app = FastAPI(
    title="CloudSentry",
    version="0.2.0",
    description="Read-only AWS security scanner using deterministic rules, with optional Bedrock explanations.",
)


class ScanRequest(BaseModel):
    region: str | None = Field(default=None, pattern=r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$", examples=["ca-central-1"])
    include_ai: bool = False


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResult)
def scan(request: ScanRequest | None = None) -> ScanResult:
    request = request or ScanRequest()
    try:
        result = run_scan(request.region)
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

    if request.include_ai:
        service = BedrockService(model_id=BEDROCK_MODEL_ID, region=BEDROCK_REGION or result.region)
        result = explain_scan(result, service)
    return result
