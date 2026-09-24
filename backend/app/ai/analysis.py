import logging

from app.ai.bedrock import AIUnavailableError, BedrockService
from app.config import AI_MAX_FINDINGS
from app.models import AIAnalysis, Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

UNEXPECTED = "AI analysis failed unexpectedly."


def select_findings(findings: list[Finding], limit: int = AI_MAX_FINDINGS) -> list[int]:
    """Indexes of the findings to explain: most severe first, INFO results excluded."""
    eligible = [i for i, finding in enumerate(findings) if finding.severity != Severity.INFO]
    return sorted(eligible, key=lambda i: findings[i].severity.rank)[:limit]


def _status(selected: int, explained: int) -> str:
    if selected == 0:
        return "skipped"
    if explained == selected:
        return "completed"
    return "partial" if explained else "unavailable"


def explain_scan(result: ScanResult, service: BedrockService, limit: int = AI_MAX_FINDINGS) -> ScanResult:
    """Attach AI explanations to a scan result. Findings are never removed and deterministic fields never change."""
    selected = select_findings(result.findings, limit)
    findings = list(result.findings)
    errors: list[str] = []
    explained = 0

    for index in selected:
        try:
            explanation = service.explain_finding(findings[index])
        except AIUnavailableError as exc:
            errors.append(str(exc))
            if exc.fatal:
                break
            continue
        except Exception:
            logger.exception("Unexpected error explaining %s", findings[index].id)
            errors.append(UNEXPECTED)
            continue
        findings[index] = findings[index].model_copy(update={"ai_explanation": explanation})
        explained += 1

    analysis = AIAnalysis(
        status=_status(len(selected), explained),
        model_id=service.model_id,
        findings_selected=len(selected),
        findings_explained=explained,
        errors=list(dict.fromkeys(errors)),
    )
    return result.model_copy(update={"findings": findings, "ai_analysis": analysis})
