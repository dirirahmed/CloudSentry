import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { jsonResponse, makeFinding, makeScanResult } from "./test/fixtures";
import type { ScanResult } from "./types";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.unstubAllGlobals();
});

/** Routes /health to "ok" and /scan to the given handler. */
function mockApi(scan: () => Promise<Response>) {
  const fetchMock = vi.fn(async (url: string) => (url.endsWith("/health") ? jsonResponse({ status: "ok" }) : scan()));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

async function renderApp() {
  root = createRoot(container);
  act(() => root.render(<App />));
  await flush();
}

function text() {
  return container.textContent ?? "";
}

function query<T extends Element>(selector: string): T {
  const element = container.querySelector<T>(selector);
  if (!element) throw new Error(`No element matches ${selector}`);
  return element;
}

function setRegion(value: string) {
  const input = query<HTMLInputElement>("#region");
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function runScanWith(result: ScanResult) {
  mockApi(async () => jsonResponse(result));
  await renderApp();
  act(() => query<HTMLButtonElement>(".scan-button").click());
  await flush();
}

describe("CloudSentry dashboard", () => {
  it("starts in the empty state and reports the API as connected", async () => {
    mockApi(async () => jsonResponse(makeScanResult()));
    await renderApp();

    expect(text()).toContain("No scan yet");
    expect(text()).toContain("API connected");
  });

  it("shows a loading state, then the findings, and sends the chosen options", async () => {
    let finish: (response: Response) => void = () => {};
    const fetchMock = mockApi(() => new Promise<Response>((resolve) => (finish = resolve)));
    await renderApp();

    setRegion("ca-central-1");
    act(() => query<HTMLInputElement>('input[role="switch"]').click());
    act(() => query<HTMLButtonElement>(".scan-button").click());

    expect(text()).toContain("Scanning your AWS account");
    expect(query<HTMLButtonElement>(".scan-button").disabled).toBe(true);

    const scanCall = fetchMock.mock.calls.find(([url]) => url.endsWith("/scan"));
    expect(JSON.parse((scanCall as unknown as [string, RequestInit])[1].body as string)).toEqual({
      include_ai: true,
      region: "ca-central-1",
    });

    finish(jsonResponse(makeScanResult()));
    await flush();

    expect(text()).not.toContain("Scanning your AWS account");
    expect(text()).toContain("SSH exposed to the internet");
    expect(text()).toContain("sg-0a1b2c3d4e5f67890");
  });

  it("renders the summary counts and finding details from the scanner", async () => {
    const findings = [
      makeFinding({ id: "IAM-001", service: "IAM", severity: "CRITICAL", title: "Policy grants full administrative access" }),
      makeFinding(),
    ];
    await runScanWith(makeScanResult(findings));

    expect(query(".count-total .count-value").textContent).toBe("2");
    expect(query(".count-button.sev-critical .count-value").textContent).toBe("1");
    expect(container.querySelectorAll(".finding-row").length).toBe(2);

    const details = query(".details");
    expect(details.textContent).toContain("Policy grants full administrative access");
    expect(details.textContent).toContain("Deterministic rule IAM-001");

    act(() => container.querySelectorAll<HTMLButtonElement>(".finding-row")[1].click());
    expect(query(".details").textContent).toContain("Restrict port 22 to known IP ranges.");
    expect(query(".details .evidence").textContent).toContain('"from_port": 22');
  });

  it("shows AI analysis separately from the scanner result", async () => {
    const finding = makeFinding({
      ai_explanation: {
        explanation: "Anyone on the internet can try to log in over SSH.",
        impact: "Automated attacks could guess or reuse weak credentials.",
        remediation: "Allow port 22 only from your own IP range.",
      },
    });
    await runScanWith(
      makeScanResult([finding], {
        ai_analysis: { status: "completed", model_id: "test-model", findings_selected: 1, findings_explained: 1, errors: [] },
      }),
    );

    const aiPanel = query(".ai-panel");
    expect(aiPanel.textContent).toContain("AI analysis");
    expect(aiPanel.textContent).toContain("Anyone on the internet can try to log in over SSH.");
    expect(aiPanel.textContent).toContain("Allow port 22 only from your own IP range.");
    expect(aiPanel.textContent).toContain("does not change the finding or its severity");
    expect(query(".scanner-result").textContent).not.toContain("Anyone on the internet");
    expect(query(".details .severity-badge").textContent).toBe("High");
    expect(text()).toContain("AI explanations were added to 1 finding.");
  });

  it("keeps findings visible when AI analysis is unavailable", async () => {
    await runScanWith(
      makeScanResult([makeFinding()], {
        ai_analysis: {
          status: "unavailable",
          model_id: null,
          findings_selected: 1,
          findings_explained: 0,
          errors: ["AI analysis is not configured. Set BEDROCK_MODEL_ID to enable it."],
        },
      }),
    );

    expect(text()).toContain("AI analysis is unavailable for this scan.");
    expect(text()).toContain("Set BEDROCK_MODEL_ID");
    expect(text()).toContain("SSH exposed to the internet");
    expect(container.querySelector(".ai-panel")).toBeNull();
    expect(text()).toContain("No AI explanation for this finding.");
  });

  it("shows a clear message when there are no findings", async () => {
    await runScanWith(makeScanResult([]));

    expect(text()).toContain("No findings");
    expect(text()).toContain("not a guarantee that the account is secure");
    expect(container.querySelector(".finding-row")).toBeNull();
  });

  it("shows the backend's error message when a scan fails", async () => {
    mockApi(async () => jsonResponse({ detail: "AWS rejected the credentials. They may be invalid or expired." }, 401));
    await renderApp();
    act(() => query<HTMLButtonElement>(".scan-button").click());
    await flush();

    expect(query('[role="alert"]').textContent).toContain("Scan failed");
    expect(text()).toContain("AWS rejected the credentials.");
  });

  it("shows a backend unavailable state when the API cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    await renderApp();
    expect(text()).toContain("API unreachable");

    act(() => query<HTMLButtonElement>(".scan-button").click());
    await flush();

    expect(query('[role="alert"]').textContent).toContain("Backend unavailable");
    expect(text()).not.toContain("TypeError");
  });

  it("blocks scans with an invalid region", async () => {
    const fetchMock = mockApi(async () => jsonResponse(makeScanResult()));
    await renderApp();

    setRegion("Canada");

    expect(query<HTMLButtonElement>(".scan-button").disabled).toBe(true);
    expect(text()).toContain("Use a region code such as ca-central-1.");
    expect(fetchMock.mock.calls.some(([url]) => url.endsWith("/scan"))).toBe(false);
  });
});
