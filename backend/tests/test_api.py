import pytest
from botocore.exceptions import EndpointConnectionError
from fastapi.testclient import TestClient

from app import main
from app.models import Finding, ScanResult, Severity
from app.scanner.scanner import CredentialsError

client = TestClient(main.app)


def fake_result():
    finding = Finding(
        id="EC2-001", service="EC2", title="SSH exposed to the internet", severity=Severity.HIGH,
        resource="sg-123456", description="d", evidence={"from_port": 22}, recommendation="r",
    )
    return ScanResult.build("123456789012", "ca-central-1", 18, [finding], [])


def raise_(exc):
    def _raise(region):
        raise exc
    return _raise


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_returns_structured_findings(monkeypatch):
    regions = []
    monkeypatch.setattr(main, "run_scan", lambda region: regions.append(region) or fake_result())

    response = client.post("/scan", json={"region": "ca-central-1"})

    assert response.status_code == 200
    body = response.json()
    assert body["account_id"] == "123456789012"
    assert body["findings_count"] == 1
    assert body["findings"][0]["severity"] == "HIGH"
    assert regions == ["ca-central-1"]


def test_scan_body_is_optional(monkeypatch):
    regions = []
    monkeypatch.setattr(main, "run_scan", lambda region: regions.append(region) or fake_result())

    assert client.post("/scan").status_code == 200
    assert regions == [None]


def test_invalid_region_is_rejected():
    assert client.post("/scan", json={"region": "not a region"}).status_code == 422


@pytest.mark.parametrize(
    "exc, status",
    [
        (CredentialsError("AWS rejected the credentials. They may be invalid or expired."), 401),
        (EndpointConnectionError(endpoint_url="https://sts.ca-central-1.amazonaws.com"), 503),
        (RuntimeError("secret-looking internal detail"), 500),
    ],
)
def test_scan_errors_map_to_safe_responses(monkeypatch, exc, status):
    monkeypatch.setattr(main, "run_scan", raise_(exc))

    response = client.post("/scan")

    assert response.status_code == status
    assert "secret-looking" not in response.text
