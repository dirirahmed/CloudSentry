import type { Finding } from "../types";
import AIExplanation from "./AIExplanation";
import SeverityBadge from "./SeverityBadge";

interface Props {
  finding: Finding;
  aiRequested: boolean;
  modelId?: string | null;
}

export default function FindingDetails({ finding, aiRequested, modelId }: Props) {
  const hasEvidence = Object.keys(finding.evidence ?? {}).length > 0;

  return (
    <article id="finding-details" className="panel details" aria-label="Finding details">
      <div className="details-heading">
        <SeverityBadge severity={finding.severity} />
        <span className="mono">{finding.id}</span>
        <span className="finding-service">{finding.service}</span>
      </div>
      <h2 className="details-title">{finding.title}</h2>
      <p className="mono details-resource">{finding.resource}</p>

      <section className="scanner-result" aria-label="Scanner result">
        <h3>
          Scanner result <span className="source-tag">Deterministic rule {finding.id}</span>
        </h3>
        <dl className="detail-list">
          <dt>Description</dt>
          <dd>{finding.description}</dd>
          <dt>Recommendation</dt>
          <dd>{finding.recommendation}</dd>
          <dt>Evidence</dt>
          <dd>
            {hasEvidence ? (
              <pre className="evidence">{JSON.stringify(finding.evidence, null, 2)}</pre>
            ) : (
              <span className="muted">No additional evidence.</span>
            )}
          </dd>
        </dl>
      </section>

      {finding.ai_explanation ? (
        <AIExplanation explanation={finding.ai_explanation} modelId={modelId} />
      ) : (
        aiRequested && (
          <p className="ai-missing">
            No AI explanation for this finding. AI analysis covers up to 10 of the most severe findings and may be
            unavailable for some.
          </p>
        )
      )}
    </article>
  );
}
