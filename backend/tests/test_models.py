import json

import pytest
from pydantic import ValidationError

from app.models import AIExplanation, Finding, ScanResult, ServiceError, Severity


def make_finding(severity=Severity.HIGH, rule_id="EC2-001", resource="sg-123456"):
    return Finding(
        id=rule_id,
        service="EC2",
        title="SSH exposed to the internet",
        severity=severity,
        resource=resource,
        description="Security group allows SSH from 0.0.0.0/0.",
        evidence={"sources": ["0.0.0.0/0"], "from_port": 22},
        recommendation="Restrict port 22.",
    )


def test_severity_order_is_deterministic():
    ranks = [s.rank for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)]
    assert ranks == sorted(ranks)


def test_severity_accepts_string_values():
    assert make_finding(severity="MEDIUM").severity is Severity.MEDIUM


def test_unknown_severity_is_rejected():
    with pytest.raises(ValidationError):
        make_finding(severity="SEVERE")


def test_finding_serialization_round_trip():
    finding = make_finding()
    payload = json.loads(finding.model_dump_json())

    assert payload["severity"] == "HIGH"
    assert payload["evidence"] == {"sources": ["0.0.0.0/0"], "from_port": 22}
    assert set(payload) == {
        "id", "service", "title", "severity", "resource", "description", "evidence", "recommendation", "ai_explanation",
    }
    assert payload["ai_explanation"] is None
    assert Finding.model_validate(payload) == finding


def test_scan_result_sorts_and_counts_findings():
    findings = [
        make_finding(Severity.LOW, "EC2-003", "sg-b"),
        make_finding(Severity.CRITICAL, "IAM-001", "policy"),
        make_finding(Severity.HIGH, "EC2-001", "sg-a"),
    ]
    errors = [ServiceError(service="S3", code="AccessDenied", message="Missing permission for ListBuckets.")]
    result = ScanResult.build("123456789012", "ca-central-1", 18, findings, errors)

    assert [f.severity for f in result.findings] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
    assert result.findings_count == 3
    assert result.severity_counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0}
    assert json.loads(result.model_dump_json())["errors"][0]["service"] == "S3"


def test_ai_explanation_ignores_extra_fields_from_the_model():
    explanation = AIExplanation.model_validate(
        {"explanation": "e", "impact": "i", "remediation": "r", "severity": "LOW", "id": "OTHER-001"}
    )
    assert explanation.model_dump() == {"explanation": "e", "impact": "i", "remediation": "r"}


def test_ai_explanation_rejects_empty_fields():
    with pytest.raises(ValidationError):
        AIExplanation(explanation=" ", impact="i", remediation="r")
