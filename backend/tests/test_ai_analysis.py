import json
from unittest.mock import MagicMock

from app.ai.analysis import UNEXPECTED, explain_scan, select_findings
from app.ai.bedrock import THROTTLED, AIUnavailableError, BedrockService
from app.models import AIExplanation, Finding, ScanResult, Severity

EXPLANATION = AIExplanation(explanation="e", impact="i", remediation="r")


def finding(rule_id, severity, resource="res"):
    return Finding(
        id=rule_id, service="EC2", title=f"{rule_id} title", severity=severity, resource=resource,
        description="d", evidence={"key": "value"}, recommendation="r",
    )


def scan_result(*findings):
    return ScanResult.build("123456789012", "ca-central-1", 5, list(findings), [])


def mock_service(side_effect=None):
    service = MagicMock(spec=BedrockService)
    service.model_id = "test-model-id"
    service.explain_finding.side_effect = side_effect or (lambda f: EXPLANATION)
    return service


def deterministic_fields(result):
    return [f.model_dump(exclude={"ai_explanation"}) for f in result.findings]


def test_explanations_are_attached_without_changing_findings():
    original = scan_result(finding("EC2-001", Severity.HIGH), finding("S3-002", Severity.MEDIUM))

    result = explain_scan(original, mock_service())

    assert all(f.ai_explanation == EXPLANATION for f in result.findings)
    assert deterministic_fields(result) == deterministic_fields(original)
    assert result.ai_analysis.status == "completed"
    assert result.ai_analysis.findings_explained == 2
    assert original.findings[0].ai_explanation is None  # the input result is not mutated


def test_most_severe_findings_are_selected_first_and_info_is_skipped():
    findings = (
        [finding(f"LOW-{i}", Severity.LOW) for i in range(5)]
        + [finding(f"HIGH-{i}", Severity.HIGH) for i in range(6)]
        + [finding("CRIT-0", Severity.CRITICAL), finding("INFO-0", Severity.INFO)]
    )
    selected = [findings[i] for i in select_findings(findings, limit=10)]

    assert len(selected) == 10
    assert selected[0].id == "CRIT-0"
    assert [f.severity for f in selected[1:7]] == [Severity.HIGH] * 6
    assert all(f.severity != Severity.INFO for f in selected)


def test_at_most_ten_findings_are_sent_to_bedrock():
    service = mock_service()
    result = explain_scan(scan_result(*[finding(f"EC2-{i}", Severity.HIGH, f"sg-{i}") for i in range(15)]), service)

    assert service.explain_finding.call_count == 10
    assert result.findings_count == 15
    assert len(result.findings) == 15
    assert sum(f.ai_explanation is not None for f in result.findings) == 10


def test_no_findings_skips_bedrock():
    service = mock_service()
    result = explain_scan(scan_result(), service)

    service.explain_finding.assert_not_called()
    assert result.ai_analysis.status == "skipped"


def test_only_info_findings_skips_bedrock():
    service = mock_service()
    result = explain_scan(scan_result(finding("CT-001", Severity.INFO)), service)

    service.explain_finding.assert_not_called()
    assert result.ai_analysis.status == "skipped"
    assert result.findings[0].ai_explanation is None


def test_one_failure_does_not_stop_the_others():
    def explain(f):
        if f.id == "EC2-002":
            raise AIUnavailableError(THROTTLED)
        return EXPLANATION

    original = scan_result(*[finding(f"EC2-00{i}", Severity.HIGH) for i in range(1, 4)])
    result = explain_scan(original, mock_service(explain))

    assert [f.ai_explanation is not None for f in result.findings] == [True, False, True]
    assert deterministic_fields(result) == deterministic_fields(original)
    assert result.ai_analysis.status == "partial"
    assert result.ai_analysis.errors == [THROTTLED]


def test_fatal_error_stops_early_and_keeps_all_findings():
    service = mock_service(AIUnavailableError("Access denied.", fatal=True))
    original = scan_result(finding("EC2-001", Severity.HIGH), finding("EC2-002", Severity.HIGH))

    result = explain_scan(original, service)

    assert service.explain_finding.call_count == 1
    assert deterministic_fields(result) == deterministic_fields(original)
    assert result.ai_analysis.status == "unavailable"
    assert result.ai_analysis.findings_explained == 0


def test_unexpected_error_is_reported_generically():
    service = mock_service(RuntimeError("raw internal detail"))
    result = explain_scan(scan_result(finding("EC2-001", Severity.HIGH)), service)

    assert result.findings_count == 1
    assert result.ai_analysis.errors == [UNEXPECTED]
    assert "raw internal detail" not in result.model_dump_json()


def test_model_output_cannot_overwrite_severity_or_id():
    client = MagicMock()
    malicious = {"explanation": "e", "impact": "i", "remediation": "r", "severity": "LOW", "id": "HACKED-001"}
    client.converse.return_value = {"output": {"message": {"content": [{"text": json.dumps(malicious)}]}}}
    service = BedrockService(model_id="test-model-id", client=client)

    result = explain_scan(scan_result(finding("EC2-001", Severity.CRITICAL)), service)

    explained = result.findings[0]
    assert explained.severity == Severity.CRITICAL
    assert explained.id == "EC2-001"
    assert explained.ai_explanation.model_dump() == {"explanation": "e", "impact": "i", "remediation": "r"}
    assert result.severity_counts["CRITICAL"] == 1
