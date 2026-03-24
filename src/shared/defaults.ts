import { SUPPORTED_SITES } from "./sites";
import type { PromptProtectSettings, RedactionMode, SiteProfile } from "./types";

export const STORAGE_KEYS = {
  settings: "settings",
  logs: "logs"
} as const;

export const MAX_LOG_ENTRIES = 150;
export const MAX_ALLOW_RULES = 200;
export const MAX_IMPORTED_RULE_PACKS = 24;
export const MAX_WORKSPACE_ALLOWLIST = 100;

export const DEFAULT_REDACTION_MODE: RedactionMode = "placeholder";

export const TEXT_ATTACHMENT_EXTENSIONS = [".txt", ".md", ".json", ".env", ".csv", ".yaml", ".yml", ".log"];

export function createDefaultSiteProfiles(): Record<string, SiteProfile> {
  return Object.fromEntries(
    SUPPORTED_SITES.flatMap((site) =>
      site.hostnames.map((hostname) => [
        hostname,
        {
          hostname,
          label: site.label,
          enabled: true,
          strictness: "balanced",
          scanOnPaste: true,
          scanAttachments: true,
          redactionMode: DEFAULT_REDACTION_MODE
        } satisfies SiteProfile
      ])
    )
  );
}

export const DEFAULT_SETTINGS: PromptProtectSettings = {
  enabled: true,
  detectSecrets: true,
  detectPII: true,
  showInlineWarnings: true,
  scanOnPaste: true,
  scanAttachments: true,
  defaultRedactionMode: DEFAULT_REDACTION_MODE,
  customPatterns: [],
  siteProfiles: createDefaultSiteProfiles(),
  exactAllowRules: [],
  workspaceAllowlist: [],
  importedRulePacks: []
};
