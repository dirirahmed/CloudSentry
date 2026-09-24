// Test-only data shaped like the backend's ScanResult. The dashboard itself never uses this file.
import type { Finding, ScanResult } from "../types";

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "EC2-001",
    service: "EC2",
    title: "SSH exposed to the internet",
    severity: "HIGH",
    resource: "sg-0a1b2c3d4e5f67890",
    description: "Security group allows SSH (TCP 22) from 0.0.0.0/0.",
    evidence: { from_port: 22, sources: ["0.0.0.0/0"] },
    recommendation: "Restrict port 22 to known IP ranges.",
    ai_explanation: null,
    ...overrides,
  };
}

export function makeScanResult(findings: Finding[] = [makeFinding()], overrides: Partial<ScanResult> = {}): ScanResult {
  const count = (severity: Finding["severity"]) => findings.filter((f) => f.severity === severity).length;
  return {
    account_id: "123456789012",
    region: "ca-central-1",
    scanned_at: "2026-09-24T12:00:00Z",
    resources_scanned: 18,
    findings_count: findings.length,
    severity_counts: {
      CRITICAL: count("CRITICAL"),
      HIGH: count("HIGH"),
      MEDIUM: count("MEDIUM"),
      LOW: count("LOW"),
      INFO: count("INFO"),
    },
    findings,
    errors: [],
    ai_analysis: null,
    ...overrides,
  };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
