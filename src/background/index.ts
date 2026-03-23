import { DEFAULT_SETTINGS, MAX_LOG_ENTRIES, STORAGE_KEYS } from "../shared/defaults";
import { SUPPORTED_SITES } from "../shared/sites";
import type { AppendLogPayload, CustomPattern, LogEntry, PromptProtectSettings, RuntimeRequest } from "../shared/types";

const SUPPORTED_HOSTS = new Set(SUPPORTED_SITES.flatMap((site) => site.hostnames));

chrome.runtime.onInstalled.addListener(() => {
  void ensureDefaults();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureDefaults();
});

chrome.action.onClicked.addListener((tab) => {
  if (tab.windowId === undefined || !chrome.sidePanel?.open) {
    return;
  }

  chrome.sidePanel.open({ windowId: tab.windowId }, () => {
    void chrome.runtime.lastError;
  });
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
  return Array.from(new Set(flags.replace(/[^dgimsuy]/g, "").split(""))).join("");
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
    enabled: candidate.enabled !== false
  };
}

function normalizeSettings(value: unknown): PromptProtectSettings {
  if (!value || typeof value !== "object") {
    return DEFAULT_SETTINGS;
  }

  const candidate = value as Partial<PromptProtectSettings>;
  const allowedHostnames = Array.isArray(candidate.allowedHostnames)
    ? Array.from(new Set(candidate.allowedHostnames.filter((hostname): hostname is string => typeof hostname === "string" && SUPPORTED_HOSTS.has(hostname))))
    : DEFAULT_SETTINGS.allowedHostnames;

  const customPatterns = Array.isArray(candidate.customPatterns)
    ? candidate.customPatterns
        .map((pattern) => normalizeCustomPattern(pattern))
        .filter((pattern): pattern is CustomPattern => pattern !== null)
    : DEFAULT_SETTINGS.customPatterns;

  return {
    enabled: candidate.enabled !== false,
    detectSecrets: candidate.detectSecrets !== false,
    detectPII: candidate.detectPII !== false,
    allowedHostnames,
    customPatterns
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
        Array.isArray(candidate.ruleLabels)
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
    ruleLabels: Array.from(new Set(payload.ruleLabels))
  };

  await storageSet({
    [STORAGE_KEYS.logs]: [entry, ...logs].slice(0, MAX_LOG_ENTRIES)
  });

  return entry;
}

