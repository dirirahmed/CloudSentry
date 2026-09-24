import type { Finding } from "../types";
import SeverityBadge from "./SeverityBadge";

interface Props {
  items: { finding: Finding; index: number }[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
}

export default function FindingsList({ items, selectedIndex, onSelect }: Props) {
  return (
    <section className="panel findings" aria-label="Findings">
      <h2 className="panel-title">
        Findings <span className="panel-count">{items.length}</span>
      </h2>
      {items.length === 0 ? (
        <p className="muted">No findings match this filter.</p>
      ) : (
        <ul className="finding-list">
          {items.map(({ finding, index }) => (
            <li key={index}>
              <button
                type="button"
                className={`finding-row sev-${finding.severity.toLowerCase()}`}
                aria-current={selectedIndex === index}
                onClick={() => onSelect(index)}
              >
                <span className="finding-row-top">
                  <SeverityBadge severity={finding.severity} />
                  <span className="mono finding-id">{finding.id}</span>
                  <span className="finding-service">{finding.service}</span>
                  {finding.ai_explanation && (
                    <span className="ai-chip" title="Has an AI explanation">
                      AI
                    </span>
                  )}
                </span>
                <span className="finding-title">{finding.title}</span>
                <span className="mono finding-resource">{finding.resource}</span>
                <span className="finding-description">{finding.description}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
