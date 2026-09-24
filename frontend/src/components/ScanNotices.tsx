import type { ScanResult } from "../types";

function AINotice({ analysis }: { analysis: NonNullable<ScanResult["ai_analysis"]> }) {
  const { status, findings_explained, findings_selected, errors } = analysis;

  const text = {
    completed: `AI explanations were added to ${findings_explained} ${findings_explained === 1 ? "finding" : "findings"}.`,
    partial: `AI analysis is partial: ${findings_explained} of ${findings_selected} selected findings were explained.`,
    unavailable: "AI analysis is unavailable for this scan. All scanner results below are complete.",
    skipped: "No findings needed an AI explanation.",
  }[status];

  const warning = status === "partial" || status === "unavailable";
  return (
    <div className={warning ? "notice notice-warning" : "notice notice-ai"} role="status">
      <p>{text}</p>
      {errors.length > 0 && (
        <ul>
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function ScanNotices({ result }: { result: ScanResult }) {
  if (result.errors.length === 0 && !result.ai_analysis) return null;

  return (
    <div className="notices">
      {result.errors.length > 0 && (
        <div className="notice notice-warning" role="status">
          <p>Some checks could not run, so these results are incomplete.</p>
          <ul>
            {result.errors.map((error) => (
              <li key={`${error.service}-${error.code}`}>
                <strong>{error.service}:</strong> {error.message}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.ai_analysis && <AINotice analysis={result.ai_analysis} />}
    </div>
  );
}
