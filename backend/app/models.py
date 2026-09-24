from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """0 is the most severe."""
        return list(Severity).index(self)


class Finding(BaseModel):
    id: str = Field(description="Rule identifier, e.g. EC2-001")
    service: str
    title: str
    severity: Severity
    resource: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str


class ServiceScan(BaseModel):
    """Output of a single service scanner."""

    findings: list[Finding] = Field(default_factory=list)
    resources_scanned: int = 0


class ServiceError(BaseModel):
    """A service scanner that could not run. Messages never include credentials."""

    service: str
    code: str
    message: str


class ScanResult(BaseModel):
    account_id: str
    region: str
    scanned_at: datetime
    resources_scanned: int
    findings_count: int
    severity_counts: dict[str, int]
    findings: list[Finding]
    errors: list[ServiceError] = Field(default_factory=list)

    @classmethod
    def build(
        cls,
        account_id: str,
        region: str,
        resources_scanned: int,
        findings: list[Finding],
        errors: list[ServiceError],
    ) -> "ScanResult":
        ordered = sorted(findings, key=lambda f: (f.severity.rank, f.service, f.id, f.resource))
        return cls(
            account_id=account_id,
            region=region,
            scanned_at=datetime.now(timezone.utc),
            resources_scanned=resources_scanned,
            findings_count=len(ordered),
            severity_counts={s.value: sum(f.severity == s for f in ordered) for s in Severity},
            findings=ordered,
            errors=errors,
        )
