import type { ScanResult, Severity } from "../types";
import SeverityBreakdown from "./SeverityBreakdown";

interface Props {
  result: ScanResult;
  filter: Severity | null;
  onFilterChange: (severity: Severity | null) => void;
}

export default function ScanSummary({ result, filter, onFilterChange }: Props) {
  const scannedAt = new Date(result.scanned_at);

  return (
    <section className="panel summary" aria-label="Scan summary">
      <dl className="scan-meta">
        <div>
          <dt>Account</dt>
          <dd className="mono">{result.account_id}</dd>
        </div>
        <div>
          <dt>Region</dt>
          <dd className="mono">{result.region}</dd>
        </div>
        <div>
          <dt>Resources checked</dt>
          <dd>{result.resources_scanned}</dd>
        </div>
        <div>
          <dt>Scanned</dt>
          <dd>{Number.isNaN(scannedAt.getTime()) ? result.scanned_at : scannedAt.toLocaleString()}</dd>
        </div>
      </dl>
      <SeverityBreakdown
        counts={result.severity_counts}
        total={result.findings_count}
        filter={filter}
        onFilterChange={onFilterChange}
      />
    </section>
  );
}
