import { SEVERITY_LABELS } from "../severity";
import type { Severity } from "../types";

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge sev-${severity.toLowerCase()}`}>{SEVERITY_LABELS[severity]}</span>;
}
