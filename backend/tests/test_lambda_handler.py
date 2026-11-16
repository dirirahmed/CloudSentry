import base64
import json

from app import main
from app.lambda_handler import handler
from app.models import Finding, ScanResult, Severity


class FakeContext:
    function_name = "cloudsentry-api"
    aws_request_id = "test-request"


def function_url_event(method: str, path: str, body: dict | None = None, base64_body: bool = False) -> dict:
    """A Lambda function URL event (payload format 2.0), as CloudFront forwards it."""
    raw = json.dumps(body) if body is not None else ""
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"content-type": "application/json", "host": "abc123.lambda-url.ca-central-1.on.aws"},
        "requestContext": {
            "accountId": "anonymous",
            "apiId": "abc123",
            "domainName": "abc123.lambda-url.ca-central-1.on.aws",
            "domainPrefix": "abc123",
            "http": {"method": method, "path": path, "protocol": "HTTP/1.1", "sourceIp": "203.0.113.9", "userAgent": "test"},
            "requestId": "test-request",
            "routeKey": "$default",
            "stage": "$default",
            "time": "15/Nov/2026:12:00:00 +0000",
            "timeEpoch": 1794744000000,
        },
        "body": base64.b64encode(raw.encode()).decode() if base64_body else raw,
        "isBase64Encoded": base64_body,
    }


def fake_result() -> ScanResult:
    finding = Finding(
        id="EC2-001", service="EC2", title="SSH exposed to the internet", severity=Severity.HIGH,
        resource="sg-123456", description="d", recommendation="r",
    )
    return ScanResult.build("123456789012", "ca-central-1", 3, [finding], [])


def test_health_through_the_api_prefix():
    response = handler(function_url_event("GET", "/api/health"), FakeContext())

    assert response["statusCode"] == 200
    assert json.loads(response["body"]) == {"status": "ok"}


def test_scan_through_the_api_prefix(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "run_scan", lambda region: calls.append(region) or fake_result())

    response = handler(
        function_url_event("POST", "/api/scan", {"region": "ca-central-1", "include_ai": False}, base64_body=True),
        FakeContext(),
    )

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["findings_count"] == 1
    assert body["findings"][0]["severity"] == "HIGH"
    assert calls == ["ca-central-1"]


def test_invalid_region_is_rejected_on_lambda():
    response = handler(function_url_event("POST", "/api/scan", {"region": "not a region"}), FakeContext())
    assert response["statusCode"] == 422


def test_unknown_path_is_not_found():
    assert handler(function_url_event("GET", "/api/docs-that-do-not-exist"), FakeContext())["statusCode"] == 404
