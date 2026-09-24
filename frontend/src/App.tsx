import { useEffect, useMemo, useState } from "react";
import { ApiError, checkHealth, runScan } from "./api";
import FindingDetails from "./components/FindingDetails";
import FindingsList from "./components/FindingsList";
import Header from "./components/Header";
import ScanControls from "./components/ScanControls";
import ScanNotices from "./components/ScanNotices";
import ScanSummary from "./components/ScanSummary";
import { EmptyState, ErrorState, LoadingState, NoFindings } from "./components/StatusPanels";
import type { ApiStatus, ScanRequest, ScanResult, Severity } from "./types";

type ScanState =
  | { status: "idle" }
  | { status: "loading"; request: ScanRequest }
  | { status: "success"; result: ScanResult }
  | { status: "error"; error: ApiError };

export default function App() {
  const [region, setRegion] = useState("");
  const [includeAi, setIncludeAi] = useState(false);
  const [scan, setScan] = useState<ScanState>({ status: "idle" });
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [filter, setFilter] = useState<Severity | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);

  useEffect(() => {
    let active = true;
    checkHealth().then((ok) => {
      if (active) setApiStatus(ok ? "online" : "offline");
    });
    return () => {
      active = false;
    };
  }, []);

  async function handleScan() {
    const request: ScanRequest = { include_ai: includeAi };
    if (region.trim()) request.region = region.trim();

    setScan({ status: "loading", request });
    setFilter(null);
    setSelectedIndex(null);
    try {
      const result = await runScan(request);
      setScan({ status: "success", result });
      setSelectedIndex(result.findings.length > 0 ? 0 : null);
      setApiStatus("online");
    } catch (err) {
      const error = err instanceof ApiError ? err : new ApiError("The scan failed unexpectedly.", "http");
      setScan({ status: "error", error });
      if (error.kind === "network" || error.kind === "unavailable") setApiStatus("offline");
    }
  }

  const result = scan.status === "success" ? scan.result : null;

  const visible = useMemo(
    () =>
      (result?.findings ?? [])
        .map((finding, index) => ({ finding, index }))
        .filter(({ finding }) => filter === null || finding.severity === filter),
    [result, filter],
  );

  function handleFilterChange(severity: Severity | null) {
    setFilter(severity);
    const first = (result?.findings ?? []).findIndex((f) => severity === null || f.severity === severity);
    setSelectedIndex(first === -1 ? null : first);
  }

  function handleSelect(index: number) {
    setSelectedIndex(index);
    // On narrow screens the details panel sits below the list, so bring it into view.
    if (window.matchMedia?.("(max-width: 900px)").matches) {
      requestAnimationFrame(() => document.getElementById("finding-details")?.scrollIntoView({ block: "start" }));
    }
  }

  const selected = result && selectedIndex !== null ? result.findings[selectedIndex] : undefined;

  return (
    <div className="app">
      <Header apiStatus={apiStatus} />
      <main>
        <ScanControls
          region={region}
          includeAi={includeAi}
          scanning={scan.status === "loading"}
          onRegionChange={setRegion}
          onIncludeAiChange={setIncludeAi}
          onScan={handleScan}
        />

        {scan.status === "idle" && <EmptyState />}
        {scan.status === "loading" && <LoadingState includeAi={scan.request.include_ai} />}
        {scan.status === "error" && <ErrorState error={scan.error} onRetry={handleScan} />}

        {result && (
          <>
            <ScanSummary result={result} filter={filter} onFilterChange={handleFilterChange} />
            <ScanNotices result={result} />
            {result.findings.length === 0 ? (
              <NoFindings />
            ) : (
              <div className="results">
                <FindingsList items={visible} selectedIndex={selectedIndex} onSelect={handleSelect} />
                {selected && (
                  <FindingDetails
                    finding={selected}
                    aiRequested={Boolean(result.ai_analysis)}
                    modelId={result.ai_analysis?.model_id}
                  />
                )}
              </div>
            )}
          </>
        )}
      </main>
      <footer className="site-footer">
        <p>
          Findings and severity come from deterministic, read-only checks. AI analysis is optional and only explains
          what the scanner found.
        </p>
      </footer>
    </div>
  );
}
