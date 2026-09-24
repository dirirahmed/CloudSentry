import { SEVERITIES, SEVERITY_LABELS } from "../severity";
import type { ScanResult, Severity } from "../types";

interface Props {
  counts: ScanResult["severity_counts"];
  total: number;
  filter: Severity | null;
  onFilterChange: (severity: Severity | null) => void;
}

export default function SeverityBreakdown({ counts, total, filter, onFilterChange }: Props) {
  const present = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);

  return (
    <div className="breakdown">
      <div className="exposure-bar" role="img" aria-label={`${total} findings by severity`}>
        {total === 0 ? (
          <span className="exposure-empty" />
        ) : (
          present.map((s) => (
            <span key={s} className={`exposure-segment sev-${s.toLowerCase()}`} style={{ flexGrow: counts[s] }} />
          ))
        )}
      </div>

      <div className="count-buttons" role="group" aria-label="Filter findings by severity">
        <button type="button" className="count-button count-total" aria-pressed={filter === null} onClick={() => onFilterChange(null)}>
          <span className="count-value">{total}</span>
          <span className="count-label">Total findings</span>
        </button>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            className={`count-button sev-${s.toLowerCase()}`}
            aria-pressed={filter === s}
            disabled={(counts[s] ?? 0) === 0}
            onClick={() => onFilterChange(filter === s ? null : s)}
          >
            <span className="count-value">{counts[s] ?? 0}</span>
            <span className="count-label">{SEVERITY_LABELS[s]}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
