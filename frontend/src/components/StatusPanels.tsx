import { useEffect, useState } from "react";
import type { ApiError } from "../api";

export function EmptyState() {
  return (
    <section className="panel state-panel">
      <h2>No scan yet</h2>
      <p>
        Choose a region and run a scan. CloudSentry makes read-only calls to IAM, S3, EC2, CloudTrail and your account
        settings using the backend's AWS credentials. Nothing in your account is changed.
      </p>
    </section>
  );
}

export function LoadingState({ includeAi }: { includeAi: boolean }) {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <section className="panel state-panel" role="status" aria-live="polite">
      <div className="spinner" aria-hidden="true" />
      <h2>Scanning your AWS account</h2>
      <p>
        Running read-only checks.
        {includeAi && " Generating AI explanations with Amazon Bedrock adds extra time."}
      </p>
      <p className="muted">{seconds}s elapsed</p>
    </section>
  );
}

const ERROR_TITLES: Record<ApiError["kind"], string> = {
  network: "Backend unavailable",
  unavailable: "Backend unavailable",
  http: "Scan failed",
  invalid_response: "Unexpected response",
};

export function ErrorState({ error, onRetry }: { error: ApiError; onRetry: () => void }) {
  return (
    <section className="panel state-panel state-error" role="alert">
      <h2>{ERROR_TITLES[error.kind]}</h2>
      <p>{error.message}</p>
      <button type="button" className="secondary-button" onClick={onRetry}>
        Try again
      </button>
    </section>
  );
}

export function NoFindings() {
  return (
    <section className="panel state-panel state-clear">
      <h2>No findings</h2>
      <p>
        None of CloudSentry's checks flagged anything in this account and region. This covers only the checks listed in
        the README; it is not a guarantee that the account is secure.
      </p>
    </section>
  );
}
