from unittest.mock import MagicMock

import pytest
from botocore.exceptions import EndpointConnectionError
from fastapi.testclient import TestClient

from app import main
from app.ai import bedrock
from app.ai.bedrock import AIUnavailableError
from app.models import AIExplanation, Finding, ScanResult, Severity
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


# Optional Bedrock analysis

EXPLANATION = AIExplanation(
    explanation="SSH is reachable from any IP address.",
    impact="Attackers can try to brute-force logins.",
    remediation="Limit port 22 to trusted ranges.",
)


def fake_bedrock(monkeypatch, side_effect=None):
    """Replace BedrockService in the API with a mock and return the mock class."""
    service_class = MagicMock()
    instance = service_class.return_value
    instance.model_id = "test-model-id"
    instance.explain_finding.side_effect = side_effect or (lambda finding: EXPLANATION)
    monkeypatch.setattr(main, "BedrockService", service_class)
    monkeypatch.setattr(main, "run_scan", lambda region: fake_result())
    return service_class


def test_include_ai_false_does_not_call_bedrock(monkeypatch):
    service_class = fake_bedrock(monkeypatch)

    response = client.post("/scan", json={"include_ai": False})

    assert response.status_code == 200
    service_class.assert_not_called()
    body = response.json()
    assert body["findings"][0]["ai_explanation"] is None
    assert body["ai_analysis"] is None


def test_include_ai_true_attaches_explanations(monkeypatch):
    service_class = fake_bedrock(monkeypatch)

    response = client.post("/scan", json={"region": "ca-central-1", "include_ai": True})

    assert response.status_code == 200
    body = response.json()
    finding = body["findings"][0]
    assert finding["id"] == "EC2-001"
    assert finding["severity"] == "HIGH"
    assert finding["evidence"] == {"from_port": 22}
    assert finding["recommendation"] == "r"
    assert finding["ai_explanation"] == EXPLANATION.model_dump()
    assert body["ai_analysis"]["status"] == "completed"
    assert body["ai_analysis"]["findings_explained"] == 1
    service_class.return_value.explain_finding.assert_called_once()


def test_bedrock_failure_still_returns_deterministic_findings(monkeypatch):
    fake_bedrock(monkeypatch, side_effect=AIUnavailableError(bedrock.ACCESS_DENIED, fatal=True))

    response = client.post("/scan", json={"include_ai": True})

    assert response.status_code == 200
    body = response.json()
    assert body["findings_count"] == 1
    assert body["findings"][0]["severity"] == "HIGH"
    assert body["findings"][0]["ai_explanation"] is None
    assert body["ai_analysis"]["status"] == "unavailable"
    assert body["ai_analysis"]["errors"] == [bedrock.ACCESS_DENIED]


def test_missing_model_id_returns_scan_with_ai_unavailable(monkeypatch):
    monkeypatch.setattr(main, "run_scan", lambda region: fake_result())
    monkeypatch.setattr(main, "BEDROCK_MODEL_ID", None)

    response = client.post("/scan", json={"include_ai": True})

    assert response.status_code == 200
    body = response.json()
    assert body["findings_count"] == 1
    assert body["ai_analysis"]["status"] == "unavailable"
    assert body["ai_analysis"]["errors"] == [bedrock.NOT_CONFIGURED]
