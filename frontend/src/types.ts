// Mirrors the Pydantic models in backend/app/models.py.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface AIExplanation {
  explanation: string;
  impact: string;
  remediation: string;
}

export interface Finding {
  id: string;
  service: string;
  title: string;
  severity: Severity;
  resource: string;
  description: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  ai_explanation?: AIExplanation | null;
}

export interface ServiceError {
  service: string;
  code: string;
  message: string;
}

export interface AIAnalysis {
  status: "completed" | "partial" | "unavailable" | "skipped";
  model_id: string | null;
  findings_selected: number;
  findings_explained: number;
  errors: string[];
}

export interface ScanResult {
  account_id: string;
  region: string;
  scanned_at: string;
  resources_scanned: number;
  findings_count: number;
  severity_counts: Partial<Record<Severity, number>>;
  findings: Finding[];
  errors: ServiceError[];
  ai_analysis?: AIAnalysis | null;
}

export interface ScanRequest {
  region?: string;
  include_ai: boolean;
}

export type ApiStatus = "checking" | "online" | "offline";
