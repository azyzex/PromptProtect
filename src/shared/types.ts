export type FindingCategory = "secret" | "pii";
export type FindingSeverity = "high" | "medium";
export type FindingSource = "builtin" | "custom";
export type PromptProtectAction = "redacted" | "cancelled";

export interface CustomPattern {
  id: string;
  label: string;
  pattern: string;
  flags: string;
  category: FindingCategory;
  enabled: boolean;
}

export interface PromptProtectSettings {
  enabled: boolean;
  detectSecrets: boolean;
  detectPII: boolean;
  allowedHostnames: string[];
  customPatterns: CustomPattern[];
}

export interface DetectionFinding {
  id: string;
  ruleId: string;
  label: string;
  category: FindingCategory;
  severity: FindingSeverity;
  source: FindingSource;
  start: number;
  end: number;
  match: string;
}

export interface DetectionSummary {
  total: number;
  secrets: number;
  pii: number;
  ruleLabels: string[];
}

export interface DetectionResult {
  findings: DetectionFinding[];
  summary: DetectionSummary;
}

export interface SupportedSite {
  id: string;
  label: string;
  hostnames: string[];
  composerSelectors: string[];
  sendButtonSelectors: string[];
}

export interface AppendLogPayload {
  hostname: string;
  siteLabel: string;
  action: PromptProtectAction;
  totalFindings: number;
  secrets: number;
  pii: number;
  ruleLabels: string[];
}

export interface LogEntry extends AppendLogPayload {
  id: string;
  timestamp: string;
}

export type RuntimeRequest =
  | { type: "promptprotect:get-settings" }
  | { type: "promptprotect:save-settings"; settings: PromptProtectSettings }
  | { type: "promptprotect:get-logs" }
  | { type: "promptprotect:clear-logs" }
  | { type: "promptprotect:append-log"; payload: AppendLogPayload };

