import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  BACKEND_UNAVAILABLE,
  BACKEND_UNREACHABLE,
  INVALID_REGION,
  INVALID_RESPONSE,
  checkHealth,
  runScan,
} from "./api";
import { jsonResponse, makeScanResult } from "./test/fixtures";

async function captureError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    return error as ApiError;
  }
  throw new Error("Expected the promise to reject");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runScan", () => {
  it("posts the request to /api/scan and returns the scan result", async () => {
    const result = makeScanResult();
    const fetchMock = vi.fn(async () => jsonResponse(result));
    vi.stubGlobal("fetch", fetchMock);

    const returned = await runScan({ region: "ca-central-1", include_ai: true });

    expect(returned).toEqual(result);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/scan");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ region: "ca-central-1", include_ai: true });
  });

  it("reports a network failure as an unreachable backend", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));

    const error = await captureError(runScan({ include_ai: false }));

    expect(error).toBeInstanceOf(ApiError);
    expect(error.kind).toBe("network");
    expect(error.message).toBe(BACKEND_UNREACHABLE);
  });

  it("shows the backend's safe error detail", async () => {
    const detail = "AWS rejected the credentials. They may be invalid or expired.";
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ detail }, 401)));

    const error = await captureError(runScan({ include_ai: false }));

    expect(error.status).toBe(401);
    expect(error.message).toBe(detail);
  });

  it("turns a validation error into a region hint", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ detail: [{ loc: ["body", "region"] }] }, 422)));

    expect((await captureError(runScan({ region: "xx", include_ai: false }))).message).toBe(INVALID_REGION);
  });

  it("treats a non-JSON gateway error as the backend being unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>502 Bad Gateway</html>", { status: 502 })));

    const error = await captureError(runScan({ include_ai: false }));

    expect(error.kind).toBe("unavailable");
    expect(error.message).toBe(BACKEND_UNAVAILABLE);
  });

  it("rejects a response that does not look like a scan result", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ findings: "nope" })));

    const error = await captureError(runScan({ include_ai: false }));

    expect(error.kind).toBe("invalid_response");
    expect(error.message).toBe(INVALID_RESPONSE);
  });
});

describe("checkHealth", () => {
  it("returns true when the API reports ok", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ status: "ok" })));
    expect(await checkHealth()).toBe(true);
  });

  it("returns false when the API cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    expect(await checkHealth()).toBe(false);
  });
});
