import { SEVERITIES } from "./severity";
import type { ScanRequest, ScanResult, Severity } from "./types";

export const API_BASE_URL = (import.meta.env.VITE_API_URL || "/api").replace(/\/+$/, "");

export const BACKEND_UNREACHABLE =
  "Cannot reach the CloudSentry API. Check that the backend is running and try again.";
export const BACKEND_UNAVAILABLE = "The CloudSentry API is not responding. Check that the backend is running.";
export const INVALID_REGION = "The region was rejected. Use an AWS region code such as ca-central-1.";
export const INVALID_RESPONSE = "The API returned a response the dashboard does not recognise.";

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
  if (detail) return new ApiError(detail, "http", status);
  if (body === undefined || status >= 502) return new ApiError(BACKEND_UNAVAILABLE, "unavailable", status);
  return new ApiError(`The scan failed (HTTP ${status}).`, "http", status);
}

export async function runScan(request: ScanRequest): Promise<ScanResult> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
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
