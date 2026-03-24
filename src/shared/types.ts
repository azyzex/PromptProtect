export type FindingCategory = "secret" | "pii";
export type FindingSeverity = "critical" | "high" | "medium";
export type FindingSource = "builtin" | "custom";
export type PromptProtectAction =
  | "redacted"
  | "cancelled"
  | "ignored_once"
  | "allowlisted"
  | "safe_rewrite"
  | "masked"
  | "pasted_flagged"
  | "attachment_flagged";
export type RedactionMode = "placeholder" | "partial-mask" | "full-redact";
export type StrictnessLevel = "relaxed" | "balanced" | "strict";
export type DetectionOrigin = "composer" | "attachment" | "test-lab";
export type ConfidenceLabel = "low" | "medium" | "high";
export type LogTrigger = "send" | "paste" | "attachment" | "test-lab";

export interface CustomPattern {
  id: string;
  label: string;
  pattern: string;
  flags: string;
  category: FindingCategory;
  enabled: boolean;
  explanation?: string;
  placeholder?: string;
}

export interface ExactAllowRule {
  id: string;
  label: string;
  hostname: string;
  ruleId: string;
  matchFingerprint: string;
  createdAt: string;
  expiresAt?: string;
}

export interface WorkspaceAllowPattern {
  id: string;
  label: string;
  pattern: string;
  flags: string;
  enabled: boolean;
}

export interface SiteProfile {
  hostname: string;
  label: string;
  enabled: boolean;
  strictness: StrictnessLevel;
  scanOnPaste: boolean;
  scanAttachments: boolean;
  redactionMode: RedactionMode;
}

export interface ImportedRulePackMeta {
  id: string;
  name: string;
  description: string;
  importedAt: string;
  patternCount: number;
}

export interface RulePackPattern {
  label: string;
  pattern: string;
  flags?: string;
  category: FindingCategory;
  explanation?: string;
  placeholder?: string;
}

export interface RulePack {
  name: string;
  description: string;
  patterns: RulePackPattern[];
}

export interface PromptProtectSettings {
  enabled: boolean;
  detectSecrets: boolean;
  detectPII: boolean;
  showInlineWarnings: boolean;
  scanOnPaste: boolean;
  scanAttachments: boolean;
  defaultRedactionMode: RedactionMode;
  customPatterns: CustomPattern[];
  siteProfiles: Record<string, SiteProfile>;
  exactAllowRules: ExactAllowRule[];
  workspaceAllowlist: WorkspaceAllowPattern[];
  importedRulePacks: ImportedRulePackMeta[];
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
  snippet: string;
  placeholder: string;
  explanation: string;
  confidence: number;
  confidenceLabel: ConfidenceLabel;
  why: string[];
  context: string;
  allowFingerprint: string;
  origin: DetectionOrigin;
}

export interface AttachmentFinding {
  id: string;
  fileName: string;
  fileType: string;
  ruleId: string;
  label: string;
  category: FindingCategory;
  severity: FindingSeverity;
  source: FindingSource;
  matchPreview: string;
  placeholder: string;
  explanation: string;
  confidence: number;
  confidenceLabel: ConfidenceLabel;
  why: string[];
  allowFingerprint: string;
}

export interface DetectionSummary {
  total: number;
  secrets: number;
  pii: number;
  critical: number;
  highConfidence: number;
  ruleLabels: string[];
  topCategory: FindingCategory | null;
}

export interface DetectionResult {
  findings: DetectionFinding[];
  summary: DetectionSummary;
}

export interface DetectionOptions {
  hostname?: string;
  origin?: DetectionOrigin;
  strictness?: StrictnessLevel;
  ignoreAllowRules?: boolean;
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
  trigger: LogTrigger;
  mode?: RedactionMode | "none";
  note?: string;
}

export interface LogEntry extends AppendLogPayload {
  id: string;
  timestamp: string;
}

export interface InlineScanSnapshot {
  type: "paste" | "attachment" | "send";
  total: number;
  at: string;
}

export interface PageDiagnostics {
  ready: boolean;
  hostname: string;
  siteLabel: string | null;
  composerFound: boolean;
  sendButtonFound: boolean;
  pendingAttachmentFlags: number;
  lastInlineScan: InlineScanSnapshot | null;
  profile: SiteProfile | null;
}

export type RuntimeRequest =
  | { type: "promptprotect:get-settings" }
  | { type: "promptprotect:save-settings"; settings: PromptProtectSettings }
  | { type: "promptprotect:get-logs" }
  | { type: "promptprotect:clear-logs" }
  | { type: "promptprotect:append-log"; payload: AppendLogPayload };

export type PageMessageRequest = { type: "promptprotect:get-page-diagnostics" };
