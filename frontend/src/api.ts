import { SEVERITIES } from "./severity";
import type { ScanRequest, ScanResult, Severity } from "./types";

export const API_BASE_URL = (import.meta.env.VITE_API_URL || "/api").replace(/\/+$/, "");

export const BACKEND_UNREACHABLE =
  "Cannot reach the CloudSentry API. Check that the backend is running and try again.";
export const BACKEND_UNAVAILABLE = "The CloudSentry API is not responding. Check that the backend is running.";
export const INVALID_REGION = "The region was rejected. Use an AWS region code such as ca-central-1.";
export const INVALID_RESPONSE = "The API returned a response the dashboard does not recognise.";
export const RATE_LIMITED = "Too many scans right now. Please wait a minute and try again.";

export type ApiErrorKind = "network" | "unavailable" | "http" | "invalid_response";

export class ApiError extends Error {
  kind: ApiErrorKind;
  status?: number;

  constructor(message: string, kind: ApiErrorKind, status?: number) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

export function isScanResult(value: unknown): value is ScanResult {
  if (!isRecord(value)) return false;
  const { account_id, region, findings, errors, severity_counts } = value;
  return (
    typeof account_id === "string" &&
    typeof region === "string" &&
    isRecord(severity_counts) &&
    Array.isArray(errors) &&
    Array.isArray(findings) &&
    findings.every(
      (f) =>
        isRecord(f) &&
        typeof f.id === "string" &&
        typeof f.title === "string" &&
        typeof f.resource === "string" &&
        SEVERITIES.includes(f.severity as Severity),
    )
  );
}

function errorFromResponse(status: number, body: unknown): ApiError {
  // FastAPI error bodies look like {"detail": "..."}. The backend only puts safe messages there.
  const detail = isRecord(body) && typeof body.detail === "string" ? body.detail.slice(0, 300) : undefined;

  if (status === 422) return new ApiError(INVALID_REGION, "http", status);
  if (status === 404) return new ApiError("The scan endpoint was not found. Check VITE_API_URL.", "http", status);
  if (status === 429) return new ApiError(detail ?? RATE_LIMITED, "http", status);
  if (detail) return new ApiError(detail, "http", status);
  if (body === undefined || status >= 502) return new ApiError(BACKEND_UNAVAILABLE, "unavailable", status);
  return new ApiError(`The scan failed (HTTP ${status}).`, "http", status);
}

/**
 * Hex SHA-256 of the request body. CloudFront signs requests to the Lambda API (origin access
 * control), and AWS requires the browser to send this hash with every POST. Returns undefined
 * where Web Crypto is unavailable (plain-HTTP pages other than localhost), which local
 * development does not need.
 */
export async function sha256Hex(text: string): Promise<string | undefined> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return undefined;
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function runScan(request: ScanRequest): Promise<ScanResult> {
  const payload = JSON.stringify(request);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const payloadHash = await sha256Hex(payload);
  if (payloadHash) headers["x-amz-content-sha256"] = payloadHash;

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/scan`, {
      method: "POST",
      headers,
      body: payload,
    });
  } catch {
    throw new ApiError(BACKEND_UNREACHABLE, "network");
  }

  const body = await readJson(response);
  if (!response.ok) throw errorFromResponse(response.status, body);
  if (!isScanResult(body)) throw new ApiError(INVALID_RESPONSE, "invalid_response", response.status);
  return body;
}

export async function checkHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const body = await readJson(response);
    return response.ok && isRecord(body) && body.status === "ok";
  } catch {
    return false;
  }
}
