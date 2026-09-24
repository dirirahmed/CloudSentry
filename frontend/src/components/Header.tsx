import type { ApiStatus } from "../types";

const STATUS_TEXT: Record<ApiStatus, string> = {
  checking: "Checking API",
  online: "API connected",
  offline: "API unreachable",
};

export default function Header({ apiStatus }: { apiStatus: ApiStatus }) {
  return (
    <header className="site-header">
      <div className="brand">
        <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
          <path d="M16 2 4 6.5v8.6C4 22.8 9.1 28 16 30c6.9-2 12-7.2 12-14.9V6.5L16 2Z" />
          <path className="brand-check" d="m10.5 16.2 3.7 3.7 7.3-7.6" />
        </svg>
        <div>
          <h1>CloudSentry</h1>
          <p>AWS security scanner</p>
        </div>
      </div>
      <p className={`api-status api-${apiStatus}`} role="status">
        <span className="api-dot" aria-hidden="true" />
        {STATUS_TEXT[apiStatus]}
      </p>
    </header>
  );
}
