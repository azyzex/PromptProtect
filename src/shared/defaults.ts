import type { PromptProtectSettings } from "./types";
import { SUPPORTED_SITES } from "./sites";

export const STORAGE_KEYS = {
  settings: "settings",
  logs: "logs"
} as const;

export const MAX_LOG_ENTRIES = 75;

export const DEFAULT_SETTINGS: PromptProtectSettings = {
  enabled: true,
  detectSecrets: true,
  detectPII: true,
  allowedHostnames: SUPPORTED_SITES.flatMap((site) => site.hostnames),
  customPatterns: []
};

