import {
  DEFAULT_REDACTION_MODE,
  DEFAULT_SETTINGS,
  MAX_ALLOW_RULES,
  MAX_IMPORTED_RULE_PACKS,
  MAX_LOG_ENTRIES,
  MAX_WORKSPACE_ALLOWLIST,
  STORAGE_KEYS,
  createDefaultSiteProfiles
} from "../shared/defaults";
import { SUPPORTED_SITES } from "../shared/sites";
import type {
  AppendLogPayload,
  CustomPattern,
  ExactAllowRule,
  ImportedRulePackMeta,
  LogEntry,
  PromptProtectSettings,
  RedactionMode,
  RuntimeRequest,
  SiteProfile,
  WorkspaceAllowPattern
} from "../shared/types";

const SUPPORTED_HOSTS = new Set(SUPPORTED_SITES.flatMap((site) => site.hostnames));

function configureSidePanelBehavior() {
  const sidePanel = (chrome as unknown as { sidePanel?: { setPanelBehavior?: (options: { openPanelOnActionClick: boolean }) => Promise<void> | void } }).sidePanel;

  if (!sidePanel?.setPanelBehavior) {
    return;
  }

  try {
    const result = sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
    if (result && typeof (result as Promise<void>).catch === "function") {
      (result as Promise<void>).catch(() => null);
    }
  } catch {
    // Ignore: side panel not available in this runtime.
  }
}

chrome.runtime.onInstalled.addListener(() => {
  void ensureDefaults();
  configureSidePanelBehavior();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureDefaults();
  configureSidePanelBehavior();
});

chrome.runtime.onMessage.addListener((message: RuntimeRequest, _sender, sendResponse) => {
  void handleMessage(message)
    .then((response) => sendResponse(response))
    .catch((error: unknown) => sendResponse({ error: error instanceof Error ? error.message : "Unknown error" }));

  return true;
});

async function handleMessage(message: RuntimeRequest) {
  switch (message.type) {
    case "promptprotect:get-settings":
      return readSettings();
    case "promptprotect:save-settings":
      return writeSettings(message.settings);
    case "promptprotect:get-logs":
      return readLogs();
    case "promptprotect:clear-logs":
      await storageSet({ [STORAGE_KEYS.logs]: [] });
      return [];
    case "promptprotect:append-log":
      return appendLog(message.payload);
    default:
      return null;
  }
}

async function storageGet<T extends Record<string, unknown>>(keys: string[]): Promise<T> {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (items) => resolve(items as T));
  });
}

async function storageSet(items: Record<string, unknown>): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set(items, () => resolve());
  });
}

function sanitizeFlags(flags: string): string {
  return Array.from(new Set(flags.replace(/[^dgimsuy]/g, "").split("").filter(Boolean))).join("");
}

function isRedactionMode(value: unknown): value is RedactionMode {
  return value === "placeholder" || value === "partial-mask" || value === "full-redact";
}

function normalizeCustomPattern(value: unknown): CustomPattern | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<CustomPattern>;

  if (typeof candidate.label !== "string" || typeof candidate.pattern !== "string" || typeof candidate.category !== "string") {
    return null;
  }

  if (candidate.category !== "secret" && candidate.category !== "pii") {
    return null;
  }

  return {
    id: typeof candidate.id === "string" && candidate.id ? candidate.id : crypto.randomUUID(),
    label: candidate.label.trim(),
    pattern: candidate.pattern,
    flags: sanitizeFlags(typeof candidate.flags === "string" ? candidate.flags : "g"),
    category: candidate.category,
    enabled: candidate.enabled !== false,
    explanation: typeof candidate.explanation === "string" ? candidate.explanation.trim() : undefined,
    placeholder: typeof candidate.placeholder === "string" ? candidate.placeholder.trim() : undefined
  };
}

function normalizeExactAllowRule(value: unknown): ExactAllowRule | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<ExactAllowRule>;

  if (
    typeof candidate.hostname !== "string" ||
    typeof candidate.ruleId !== "string" ||
    typeof candidate.matchFingerprint !== "string" ||
    !SUPPORTED_HOSTS.has(candidate.hostname)
  ) {
    return null;
  }

  return {
    id: typeof candidate.id === "string" && candidate.id ? candidate.id : crypto.randomUUID(),
    label: typeof candidate.label === "string" ? candidate.label.trim() : "Allowlisted finding",
    hostname: candidate.hostname,
    ruleId: candidate.ruleId,
    matchFingerprint: candidate.matchFingerprint,
    createdAt: typeof candidate.createdAt === "string" ? candidate.createdAt : new Date().toISOString(),
    expiresAt:
      typeof candidate.expiresAt === "string" && candidate.expiresAt && !Number.isNaN(Date.parse(candidate.expiresAt))
        ? candidate.expiresAt
        : undefined
  };
}

function normalizeWorkspaceAllowPattern(value: unknown): WorkspaceAllowPattern | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<WorkspaceAllowPattern>;

  if (typeof candidate.label !== "string" || typeof candidate.pattern !== "string") {
    return null;
  }

  return {
    id: typeof candidate.id === "string" && candidate.id ? candidate.id : crypto.randomUUID(),
    label: candidate.label.trim(),
    pattern: candidate.pattern,
    flags: sanitizeFlags(typeof candidate.flags === "string" ? candidate.flags : "g"),
    enabled: candidate.enabled !== false
  };
}

function normalizeImportedRulePackMeta(value: unknown): ImportedRulePackMeta | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const candidate = value as Partial<ImportedRulePackMeta>;

  if (typeof candidate.name !== "string" || typeof candidate.description !== "string" || typeof candidate.patternCount !== "number") {
    return null;
  }

  return {
    id: typeof candidate.id === "string" && candidate.id ? candidate.id : crypto.randomUUID(),
    name: candidate.name.trim(),
    description: candidate.description.trim(),
    importedAt: typeof candidate.importedAt === "string" ? candidate.importedAt : new Date().toISOString(),
    patternCount: candidate.patternCount
  };
}

function normalizeSiteProfile(hostname: string, value: unknown): SiteProfile {
  const defaults = createDefaultSiteProfiles()[hostname];

  if (!value || typeof value !== "object") {
    return defaults;
  }

  const candidate = value as Partial<SiteProfile>;

  return {
    hostname,
    label: typeof candidate.label === "string" ? candidate.label : defaults.label,
    enabled: candidate.enabled !== false,
    strictness:
      candidate.strictness === "relaxed" || candidate.strictness === "balanced" || candidate.strictness === "strict"
        ? candidate.strictness
        : defaults.strictness,
    scanOnPaste: candidate.scanOnPaste !== false,
    scanAttachments: candidate.scanAttachments !== false,
    redactionMode: isRedactionMode(candidate.redactionMode) ? candidate.redactionMode : defaults.redactionMode
  };
}

function normalizeSettings(value: unknown): PromptProtectSettings {
  const defaultProfiles = createDefaultSiteProfiles();

  if (!value || typeof value !== "object") {
    return {
      ...DEFAULT_SETTINGS,
      siteProfiles: defaultProfiles
    };
  }

  const candidate = value as Partial<PromptProtectSettings> & { allowedHostnames?: unknown };
  const legacyAllowedHostnames = Array.isArray(candidate.allowedHostnames)
    ? new Set(candidate.allowedHostnames.filter((hostname): hostname is string => typeof hostname === "string" && SUPPORTED_HOSTS.has(hostname)))
    : null;

  const siteProfiles = Object.fromEntries(
    Object.keys(defaultProfiles).map((hostname) => {
      const profile = normalizeSiteProfile(hostname, candidate.siteProfiles?.[hostname]);

      if (legacyAllowedHostnames) {
        profile.enabled = legacyAllowedHostnames.has(hostname);
      }

      return [hostname, profile];
    })
  );

  const customPatterns = Array.isArray(candidate.customPatterns)
    ? candidate.customPatterns
        .map((pattern) => normalizeCustomPattern(pattern))
        .filter((pattern): pattern is CustomPattern => pattern !== null)
    : [];

  const now = Date.now();
  const exactAllowRules = Array.isArray(candidate.exactAllowRules)
    ? candidate.exactAllowRules
        .map((rule) => normalizeExactAllowRule(rule))
        .filter((rule): rule is ExactAllowRule => rule !== null)
        .filter((rule) => (rule.expiresAt ? Date.parse(rule.expiresAt) > now : true))
        .slice(0, MAX_ALLOW_RULES)
    : [];

  const workspaceAllowlist = Array.isArray(candidate.workspaceAllowlist)
    ? candidate.workspaceAllowlist
        .map((pattern) => normalizeWorkspaceAllowPattern(pattern))
        .filter((pattern): pattern is WorkspaceAllowPattern => pattern !== null)
        .slice(0, MAX_WORKSPACE_ALLOWLIST)
    : [];

  const importedRulePacks = Array.isArray(candidate.importedRulePacks)
    ? candidate.importedRulePacks
        .map((meta) => normalizeImportedRulePackMeta(meta))
        .filter((meta): meta is ImportedRulePackMeta => meta !== null)
        .slice(0, MAX_IMPORTED_RULE_PACKS)
    : [];

  return {
    enabled: candidate.enabled !== false,
    detectSecrets: candidate.detectSecrets !== false,
    detectPII: candidate.detectPII !== false,
    showInlineWarnings: candidate.showInlineWarnings !== false,
    scanOnPaste: candidate.scanOnPaste !== false,
    scanAttachments: candidate.scanAttachments !== false,
    defaultRedactionMode: isRedactionMode(candidate.defaultRedactionMode) ? candidate.defaultRedactionMode : DEFAULT_REDACTION_MODE,
    customPatterns,
    siteProfiles,
    exactAllowRules,
    workspaceAllowlist,
    importedRulePacks
  };
}

function normalizeLogs(value: unknown): LogEntry[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((entry): entry is LogEntry => {
      if (!entry || typeof entry !== "object") {
        return false;
      }

      const candidate = entry as Partial<LogEntry>;
      return (
        typeof candidate.id === "string" &&
        typeof candidate.timestamp === "string" &&
        typeof candidate.hostname === "string" &&
        typeof candidate.siteLabel === "string" &&
        typeof candidate.action === "string" &&
        typeof candidate.totalFindings === "number" &&
        typeof candidate.secrets === "number" &&
        typeof candidate.pii === "number" &&
        Array.isArray(candidate.ruleLabels) &&
        typeof candidate.trigger === "string"
      );
    })
    .slice(0, MAX_LOG_ENTRIES);
}

async function ensureDefaults(): Promise<void> {
  const items = await storageGet<{ settings?: unknown; logs?: unknown }>([STORAGE_KEYS.settings, STORAGE_KEYS.logs]);

  await storageSet({
    [STORAGE_KEYS.settings]: normalizeSettings(items.settings),
    [STORAGE_KEYS.logs]: normalizeLogs(items.logs)
  });
}

async function readSettings(): Promise<PromptProtectSettings> {
  const items = await storageGet<{ settings?: unknown }>([STORAGE_KEYS.settings]);
  const settings = normalizeSettings(items.settings);
  await storageSet({ [STORAGE_KEYS.settings]: settings });
  return settings;
}

async function writeSettings(settings: PromptProtectSettings): Promise<PromptProtectSettings> {
  const normalized = normalizeSettings(settings);
  await storageSet({ [STORAGE_KEYS.settings]: normalized });
  return normalized;
}

async function readLogs(): Promise<LogEntry[]> {
  const items = await storageGet<{ logs?: unknown }>([STORAGE_KEYS.logs]);
  const logs = normalizeLogs(items.logs);
  await storageSet({ [STORAGE_KEYS.logs]: logs });
  return logs;
}

async function appendLog(payload: AppendLogPayload): Promise<LogEntry> {
  const logs = await readLogs();

  const entry: LogEntry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    hostname: payload.hostname,
    siteLabel: payload.siteLabel,
    action: payload.action,
    totalFindings: payload.totalFindings,
    secrets: payload.secrets,
    pii: payload.pii,
    ruleLabels: Array.from(new Set(payload.ruleLabels)),
    trigger: payload.trigger,
    mode: payload.mode ?? "none",
    note: payload.note
  };

  await storageSet({
    [STORAGE_KEYS.logs]: [entry, ...logs].slice(0, MAX_LOG_ENTRIES)
  });

  return entry;
}
