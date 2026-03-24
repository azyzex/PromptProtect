import { STORAGE_KEYS } from "../shared/defaults";
import { detectSensitiveContent } from "../shared/detector";
import { buildReplacementPreviewHtml, redactionModeLabel } from "../shared/redaction";
import { runtimeApi } from "../shared/runtime";
import { STARTER_RULE_PACKS } from "../shared/rule-packs";
import { SUPPORTED_SITES } from "../shared/sites";
import type {
  CustomPattern,
  ExactAllowRule,
  ImportedRulePackMeta,
  LogEntry,
  PageDiagnostics,
  PromptProtectSettings,
  RedactionMode,
  RulePack,
  RulePackPattern,
  SiteProfile,
  WorkspaceAllowPattern
} from "../shared/types";
import { countLogsLastDays, escapeHtml, formatTimestamp, topCategory, topRuleLabel } from "./utils";

const masterToggle = document.getElementById("master-toggle") as HTMLButtonElement;
const heroStats = document.getElementById("hero-stats") as HTMLDivElement;
const heroAnalytics = document.getElementById("hero-analytics") as HTMLDivElement;
const guardrailCaption = document.getElementById("guardrail-caption") as HTMLSpanElement;
const controlGrid = document.getElementById("control-grid") as HTMLDivElement;
const siteGrid = document.getElementById("site-grid") as HTMLDivElement;
const workspaceAllowForm = document.getElementById("workspace-allow-form") as HTMLFormElement;
const workspaceAllowlist = document.getElementById("workspace-allowlist") as HTMLDivElement;
const allowStatus = document.getElementById("allow-status") as HTMLParagraphElement;
const exactAllowStatus = document.getElementById("exact-allow-status") as HTMLParagraphElement;
const exactAllowlist = document.getElementById("exact-allowlist") as HTMLDivElement;
const customPatternList = document.getElementById("custom-pattern-list") as HTMLDivElement;
const logList = document.getElementById("log-list") as HTMLDivElement;
const clearLogsButton = document.getElementById("clear-logs-button") as HTMLButtonElement;
const customRuleForm = document.getElementById("custom-rule-form") as HTMLFormElement;
const formStatus = document.getElementById("form-status") as HTMLParagraphElement;
const loadStarterPackButton = document.getElementById("load-starter-pack") as HTMLButtonElement;
const exportRulePackButton = document.getElementById("export-rule-pack") as HTMLButtonElement;
const importRulePackButton = document.getElementById("import-rule-pack") as HTMLButtonElement;
const rulePackStatus = document.getElementById("rule-pack-status") as HTMLParagraphElement;
const rulePackJson = document.getElementById("rule-pack-json") as HTMLTextAreaElement;
const importedRulePacks = document.getElementById("imported-rule-packs") as HTMLDivElement;
const testLabInput = document.getElementById("test-lab-input") as HTMLTextAreaElement;
const testLabModes = document.getElementById("test-lab-modes") as HTMLDivElement;
const runTestLabButton = document.getElementById("run-test-lab") as HTMLButtonElement;
const testLabOutput = document.getElementById("test-lab-output") as HTMLDivElement;
const diagnosticsPanel = document.getElementById("diagnostics-panel") as HTMLDivElement;
const refreshDiagnosticsButton = document.getElementById("refresh-diagnostics") as HTMLButtonElement;

let settings: PromptProtectSettings;
let logs: LogEntry[] = [];
let diagnostics: PageDiagnostics | null = null;
let diagnosticsStatus = "Loading active tab diagnostics...";
let testLabMode: RedactionMode = "placeholder";

void init();

async function init() {
  const [loadedSettings, loadedLogs] = await Promise.all([runtimeApi.getSettings(), runtimeApi.getLogs()]);
  settings = loadedSettings;
  logs = loadedLogs;

  bindListeners();
  render();
  void refreshDiagnostics();

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") {
      return;
    }

    if (changes[STORAGE_KEYS.settings]?.newValue) {
      settings = changes[STORAGE_KEYS.settings].newValue as PromptProtectSettings;
      render();
    }

    if (changes[STORAGE_KEYS.logs]?.newValue) {
      logs = changes[STORAGE_KEYS.logs].newValue as LogEntry[];
      render();
    }
  });
}

function bindListeners() {
  masterToggle.addEventListener("click", async () => {
    await saveSettings({ enabled: !settings.enabled });
  });

  controlGrid.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const control = target.closest<HTMLElement>("[data-control]")?.dataset.control;

    if (!control) {
      return;
    }

    if (control === "detectSecrets") {
      await saveSettings({ detectSecrets: !settings.detectSecrets });
      return;
    }

    if (control === "detectPII") {
      await saveSettings({ detectPII: !settings.detectPII });
      return;
    }

    if (control === "scanOnPaste") {
      await saveSettings({ scanOnPaste: !settings.scanOnPaste });
      return;
    }

    if (control === "scanAttachments") {
      await saveSettings({ scanAttachments: !settings.scanAttachments });
      return;
    }

    if (control === "showInlineWarnings") {
      await saveSettings({ showInlineWarnings: !settings.showInlineWarnings });
      return;
    }

    if (control === "defaultRedactionMode") {
      await saveSettings({ defaultRedactionMode: cycleRedactionMode(settings.defaultRedactionMode) });
    }
  });

  siteGrid.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const actionTarget = target.closest<HTMLElement>("[data-site-action]");

    if (!actionTarget) {
      return;
    }

    const hostname = actionTarget.dataset.hostname;
    const action = actionTarget.dataset.siteAction;

    if (!hostname || !action) {
      return;
    }

    const profile = settings.siteProfiles[hostname];

    if (!profile) {
      return;
    }

    let nextProfile: SiteProfile = profile;

    if (action === "toggle") {
      nextProfile = { ...profile, enabled: !profile.enabled };
    } else if (action === "strictness") {
      nextProfile = { ...profile, strictness: cycleStrictness(profile.strictness) };
    } else if (action === "paste") {
      nextProfile = { ...profile, scanOnPaste: !profile.scanOnPaste };
    } else if (action === "attachments") {
      nextProfile = { ...profile, scanAttachments: !profile.scanAttachments };
    } else if (action === "mode") {
      nextProfile = { ...profile, redactionMode: cycleRedactionMode(profile.redactionMode) };
    }

    await saveSettings({
      siteProfiles: {
        ...settings.siteProfiles,
        [hostname]: nextProfile
      }
    });
  });

  workspaceAllowForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    allowStatus.textContent = "";

    const formData = new FormData(workspaceAllowForm);
    const label = String(formData.get("label") ?? "").trim();
    const pattern = String(formData.get("pattern") ?? "").trim();
    const flags = normalizeFlags(String(formData.get("flags") ?? "g"));

    if (!label || !pattern) {
      allowStatus.textContent = "Add a label and regex pattern.";
      return;
    }

    try {
      new RegExp(pattern, ensureGlobal(flags));
    } catch {
      allowStatus.textContent = "That allowlist regex is not valid.";
      return;
    }

    const nextPattern: WorkspaceAllowPattern = {
      id: crypto.randomUUID(),
      label,
      pattern,
      flags,
      enabled: true
    };

    await saveSettings({
      workspaceAllowlist: [...settings.workspaceAllowlist, nextPattern]
    });

    workspaceAllowForm.reset();
    (document.getElementById("allow-flags") as HTMLInputElement).value = "g";
    allowStatus.textContent = "Workspace allow rule added.";
  });

  workspaceAllowlist.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const action = target.closest<HTMLElement>("[data-allow-action]")?.dataset.allowAction;
    const id = target.closest<HTMLElement>("[data-pattern-id]")?.dataset.patternId;

    if (!action || !id) {
      return;
    }

    if (action === "toggle") {
      await saveSettings({
        workspaceAllowlist: settings.workspaceAllowlist.map((pattern) =>
          pattern.id === id ? { ...pattern, enabled: !pattern.enabled } : pattern
        )
      });
      return;
    }

    if (action === "remove") {
      await saveSettings({
        workspaceAllowlist: settings.workspaceAllowlist.filter((pattern) => pattern.id !== id)
      });
    }
  });

  exactAllowlist.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const action = target.closest<HTMLElement>("[data-exact-allow-action]")?.dataset.exactAllowAction;
    const id = target.closest<HTMLElement>("[data-exact-allow-id]")?.dataset.exactAllowId;

    if (!action || !id) {
      return;
    }

    if (action === "remove") {
      await saveSettings({
        exactAllowRules: settings.exactAllowRules.filter((rule) => rule.id !== id)
      });
    }
  });

  customRuleForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    formStatus.textContent = "";

    const formData = new FormData(customRuleForm);
    const label = String(formData.get("label") ?? "").trim();
    const pattern = String(formData.get("pattern") ?? "").trim();
    const category = String(formData.get("category") ?? "secret");
    const flags = normalizeFlags(String(formData.get("flags") ?? "g"));
    const placeholder = String(formData.get("placeholder") ?? "").trim();
    const explanation = String(formData.get("explanation") ?? "").trim();

    if (!label || !pattern || (category !== "secret" && category !== "pii")) {
      formStatus.textContent = "Add a label, regex pattern, and category.";
      return;
    }

    try {
      new RegExp(pattern, ensureGlobal(flags));
    } catch {
      formStatus.textContent = "That regex pattern is not valid.";
      return;
    }

    const nextPattern: CustomPattern = {
      id: crypto.randomUUID(),
      label,
      pattern,
      flags,
      category,
      enabled: true,
      placeholder: placeholder || undefined,
      explanation: explanation || undefined
    };

    await saveSettings({
      customPatterns: [...settings.customPatterns, nextPattern]
    });

    customRuleForm.reset();
    (document.getElementById("rule-flags") as HTMLInputElement).value = "g";
    formStatus.textContent = "Custom rule added.";
  });

  customPatternList.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const action = target.closest<HTMLElement>("[data-pattern-action]")?.dataset.patternAction;
    const id = target.closest<HTMLElement>("[data-pattern-id]")?.dataset.patternId;

    if (!action || !id) {
      return;
    }

    if (action === "toggle") {
      await saveSettings({
        customPatterns: settings.customPatterns.map((pattern) =>
          pattern.id === id ? { ...pattern, enabled: !pattern.enabled } : pattern
        )
      });
      return;
    }

    if (action === "remove") {
      await saveSettings({
        customPatterns: settings.customPatterns.filter((pattern) => pattern.id !== id)
      });
    }
  });

  clearLogsButton.addEventListener("click", async () => {
    logs = await runtimeApi.clearLogs();
    render();
  });

  loadStarterPackButton.addEventListener("click", async () => {
    await importRulePack(STARTER_RULE_PACKS[0]);
    rulePackStatus.textContent = "Starter rule pack imported.";
  });

  exportRulePackButton.addEventListener("click", () => {
    const pack: RulePack = {
      name: "PromptProtect export",
      description: "Exported custom PromptProtect rules.",
      patterns: settings.customPatterns.map((pattern) => ({
        label: pattern.label,
        pattern: pattern.pattern,
        flags: pattern.flags,
        category: pattern.category,
        explanation: pattern.explanation,
        placeholder: pattern.placeholder
      }))
    };

    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "promptprotect-rule-pack.json";
    anchor.click();
    URL.revokeObjectURL(url);
  });

  importRulePackButton.addEventListener("click", async () => {
    rulePackStatus.textContent = "";

    try {
      const parsed = JSON.parse(rulePackJson.value) as RulePack;
      await importRulePack(parsed);
      rulePackStatus.textContent = "Rule pack imported.";
      rulePackJson.value = "";
    } catch {
      rulePackStatus.textContent = "That rule pack JSON could not be parsed.";
    }
  });

  testLabModes.addEventListener("click", (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const mode = target.closest<HTMLElement>("[data-lab-mode]")?.dataset.labMode;

    if (!mode) {
      return;
    }

    testLabMode = mode as RedactionMode;
    renderTestLab();
  });

  runTestLabButton.addEventListener("click", () => {
    renderTestLab();
  });

  refreshDiagnosticsButton.addEventListener("click", () => {
    void refreshDiagnostics();
  });
}

function normalizeFlags(flags: string): string {
  return Array.from(new Set(flags.replace(/[^dgimsuy]/g, "").split("").filter(Boolean))).join("");
}

function ensureGlobal(flags: string): string {
  return flags.includes("g") ? flags : `${flags}g`;
}

function cycleStrictness(value: SiteProfile["strictness"]): SiteProfile["strictness"] {
  if (value === "relaxed") {
    return "balanced";
  }

  if (value === "balanced") {
    return "strict";
  }

  return "relaxed";
}

function cycleRedactionMode(value: RedactionMode): RedactionMode {
  if (value === "placeholder") {
    return "partial-mask";
  }

  if (value === "partial-mask") {
    return "full-redact";
  }

  return "placeholder";
}

async function saveSettings(partial: Partial<PromptProtectSettings>) {
  settings = await runtimeApi.saveSettings({
    ...settings,
    ...partial
  });
  render();
}

async function importRulePack(input: RulePack) {
  const patterns = Array.isArray(input.patterns) ? input.patterns : [];
  const nextPatterns = patterns
    .filter((pattern): pattern is RulePackPattern => Boolean(pattern && typeof pattern === "object"))
    .filter((pattern) => typeof pattern.label === "string" && typeof pattern.pattern === "string" && typeof pattern.category === "string")
    .map<CustomPattern>((pattern) => ({
      id: crypto.randomUUID(),
      label: pattern.label.trim(),
      pattern: pattern.pattern,
      flags: normalizeFlags(pattern.flags ?? "g"),
      category: pattern.category,
      enabled: true,
      explanation: pattern.explanation?.trim() || undefined,
      placeholder: pattern.placeholder?.trim() || undefined
    }));

  const meta: ImportedRulePackMeta = {
    id: crypto.randomUUID(),
    name: typeof input.name === "string" ? input.name : "Imported pack",
    description: typeof input.description === "string" ? input.description : "Imported PromptProtect rule pack.",
    importedAt: new Date().toISOString(),
    patternCount: nextPatterns.length
  };

  await saveSettings({
    customPatterns: [...settings.customPatterns, ...nextPatterns],
    importedRulePacks: [meta, ...settings.importedRulePacks]
  });
}

async function refreshDiagnostics() {
  diagnosticsStatus = "Loading active tab diagnostics...";
  diagnostics = null;
  renderDiagnostics();

  const tab = await getActiveTab();

  if (!tab?.id) {
    diagnosticsStatus = "No active tab available.";
    renderDiagnostics();
    return;
  }

  try {
    diagnostics = await sendDiagnosticsMessage(tab.id);
    diagnosticsStatus = diagnostics.ready ? "Connected to supported page." : "PromptProtect is not attached to the current page.";
  } catch {
    diagnosticsStatus = "Open ChatGPT, Claude, or Gemini in the active tab to view live adapter diagnostics.";
  }

  renderDiagnostics();
}

function getActiveTab(): Promise<chrome.tabs.Tab | null> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => resolve(tabs[0] ?? null));
  });
}

function sendDiagnosticsMessage(tabId: number): Promise<PageDiagnostics> {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "promptprotect:get-page-diagnostics" }, (response: PageDiagnostics) => {
      const error = chrome.runtime.lastError;

      if (error) {
        reject(new Error(error.message));
        return;
      }

      resolve(response);
    });
  });
}

function render() {
  renderHero();
  renderControls();
  renderSites();
  renderWorkspaceAllowlist();
  renderExactAllowRules();
  renderCustomPatterns();
  renderRulePacks();
  renderTestLab();
  renderDiagnostics();
  renderLogs();
}

function formatExpiry(rule: ExactAllowRule): string {
  if (!rule.expiresAt) {
    return "permanent";
  }

  const ms = Date.parse(rule.expiresAt) - Date.now();
  const minutes = Math.max(0, Math.floor(ms / 60_000));

  if (minutes <= 0) {
    return "expired";
  }

  if (minutes < 60) {
    return `expires in ${minutes}m`;
  }

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  if (hours < 24) {
    return `expires in ${hours}h${remainingMinutes ? ` ${remainingMinutes}m` : ""}`;
  }

  const days = Math.floor(hours / 24);
  return `expires in ${days}d`;
}

function renderExactAllowRules() {
  exactAllowStatus.textContent = "";

  if (!settings.exactAllowRules.length) {
    exactAllowlist.innerHTML = `<div class="empty-state">No per-site allow rules yet. Use "Allow" in the review modal to suppress known-safe matches.</div>`;
    return;
  }

  exactAllowlist.innerHTML = settings.exactAllowRules
    .slice(0, 120)
    .map(
      (rule) => `
        <article class="pattern-card" data-exact-allow-id="${escapeHtml(rule.id)}">
          <div class="pattern-top">
            <strong>${escapeHtml(rule.label)}</strong>
            <span class="pill neutral">${escapeHtml(formatExpiry(rule))}</span>
          </div>
          <p class="meta">${escapeHtml(rule.hostname)} · ${escapeHtml(rule.ruleId)} · added ${escapeHtml(formatTimestamp(rule.createdAt))}${rule.expiresAt ? ` · expires ${escapeHtml(formatTimestamp(rule.expiresAt))}` : ""}</p>
          <div class="pattern-actions">
            <button type="button" class="pattern-action is-danger" data-exact-allow-action="remove" data-exact-allow-id="${escapeHtml(rule.id)}">Remove</button>
          </div>
        </article>
      `
    )
    .join("");
}

function renderHero() {
  masterToggle.classList.toggle("is-off", !settings.enabled);
  masterToggle.textContent = settings.enabled ? "Shield On" : "Shield Off";

  heroStats.innerHTML = `
    <article class="stat-card">
      <span class="small-note">Protected sites</span>
      <strong>${Object.values(settings.siteProfiles).filter((profile) => profile.enabled).length}</strong>
    </article>
    <article class="stat-card">
      <span class="small-note">Custom rules</span>
      <strong>${settings.customPatterns.length}</strong>
    </article>
    <article class="stat-card">
      <span class="small-note">Allow rules</span>
      <strong>${settings.workspaceAllowlist.length + settings.exactAllowRules.length}</strong>
    </article>
    <article class="stat-card">
      <span class="small-note">Flagged sends</span>
      <strong>${logs.length}</strong>
    </article>
  `;

  heroAnalytics.innerHTML = `
    <article class="analytics-card">
      <span class="small-note">Last 7 days</span>
      <strong>${countLogsLastDays(logs, 7)}</strong>
    </article>
    <article class="analytics-card">
      <span class="small-note">Top category</span>
      <strong>${escapeHtml(topCategory(logs))}</strong>
    </article>
    <article class="analytics-card">
      <span class="small-note">Top rule</span>
      <strong>${escapeHtml(topRuleLabel(logs))}</strong>
    </article>
    <article class="analytics-card">
      <span class="small-note">Default rewrite</span>
      <strong>${escapeHtml(redactionModeLabel(settings.defaultRedactionMode))}</strong>
    </article>
  `;

  guardrailCaption.textContent = settings.enabled ? "Local blocking active" : "Blocking paused";
}

function renderControls() {
  controlGrid.innerHTML = [
    renderControlCard("detectSecrets", "Secrets", "Structured secret detection", "OpenAI, AWS, GitHub, JWTs, bearer tokens, .env assignments, connection strings.", settings.detectSecrets, "secret"),
    renderControlCard("detectPII", "PII", "Email and phone review", "Catch basic identity leaks before prompts leave the browser.", settings.detectPII, "pii"),
    renderControlCard("scanOnPaste", "Paste", "Scan pasted text", "Warn as soon as risky content lands in the composer.", settings.scanOnPaste, "neutral"),
    renderControlCard("scanAttachments", "Files", "Scan text attachments", "Inspect .txt, .md, .json, .env, .csv, and similar files locally.", settings.scanAttachments, "neutral"),
    renderControlCard("showInlineWarnings", "Inline", "Show floating warnings", "Display heads-up chips near the composer after paste or file scans.", settings.showInlineWarnings, "neutral"),
    renderControlCard("defaultRedactionMode", "Rewrite", redactionModeLabel(settings.defaultRedactionMode), "Cycle the default rewrite style used for new site profiles.", true, "neutral")
  ].join("");
}

function renderControlCard(
  key: string,
  eyebrow: string,
  title: string,
  description: string,
  active: boolean,
  tone: "secret" | "pii" | "neutral"
): string {
  return `
    <button type="button" class="toggle-card ${active ? "is-active" : ""} ${tone === "secret" ? "is-secret" : tone === "pii" ? "is-pii" : ""}" data-control="${key}">
      <span class="toggle-card__eyebrow">${escapeHtml(eyebrow)}</span>
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(description)}</p>
      <span class="toggle-card__state">${key === "defaultRedactionMode" ? "Cycle mode" : active ? "Enabled" : "Disabled"}</span>
    </button>
  `;
}

function renderSites() {
  siteGrid.innerHTML = SUPPORTED_SITES.flatMap((site) =>
    site.hostnames.map((hostname) => {
      const profile = settings.siteProfiles[hostname];
      const isActive = profile?.enabled;

      return `
        <article class="site-pill ${isActive ? "is-active" : ""}">
          <div class="site-meta">
            <div>
              <strong>${escapeHtml(site.label)}</strong>
              <span>${escapeHtml(hostname)}</span>
            </div>
            <span class="site-status">${isActive ? "Watching" : "Paused"}</span>
          </div>
          <div class="site-pill__actions">
            <button type="button" class="site-action" data-site-action="toggle" data-hostname="${hostname}">${isActive ? "Disable" : "Enable"}</button>
            <button type="button" class="site-action" data-site-action="strictness" data-hostname="${hostname}">${escapeHtml(profile.strictness)}</button>
            <button type="button" class="site-action" data-site-action="mode" data-hostname="${hostname}">${escapeHtml(redactionModeLabel(profile.redactionMode))}</button>
            <button type="button" class="site-action" data-site-action="paste" data-hostname="${hostname}">Paste ${profile.scanOnPaste ? "On" : "Off"}</button>
            <button type="button" class="site-action" data-site-action="attachments" data-hostname="${hostname}">Files ${profile.scanAttachments ? "On" : "Off"}</button>
          </div>
        </article>
      `;
    })
  ).join("");
}

function renderWorkspaceAllowlist() {
  if (!settings.workspaceAllowlist.length) {
    workspaceAllowlist.innerHTML = `<div class="empty-state">No workspace allowlist patterns yet. Add safe demo tokens or internal patterns here.</div>`;
    return;
  }

  workspaceAllowlist.innerHTML = settings.workspaceAllowlist
    .map(
      (pattern) => `
        <article class="pattern-card" data-pattern-id="${pattern.id}">
          <div class="pattern-top">
            <strong>${escapeHtml(pattern.label)}</strong>
            <span class="pill neutral">${pattern.enabled ? "enabled" : "disabled"}</span>
          </div>
          <code>/${escapeHtml(pattern.pattern)}/${escapeHtml(pattern.flags || "g")}</code>
          <div class="pattern-actions">
            <button type="button" class="pattern-action" data-allow-action="toggle" data-pattern-id="${pattern.id}">${pattern.enabled ? "Disable" : "Enable"}</button>
            <button type="button" class="pattern-action is-danger" data-allow-action="remove" data-pattern-id="${pattern.id}">Remove</button>
          </div>
        </article>
      `
    )
    .join("");
}

function renderCustomPatterns() {
  if (!settings.customPatterns.length) {
    customPatternList.innerHTML = `<div class="empty-state">No custom rules yet. Add one above for company-specific tokens or identifiers.</div>`;
    return;
  }

  customPatternList.innerHTML = settings.customPatterns
    .map(
      (pattern) => `
        <article class="pattern-card" data-pattern-id="${pattern.id}">
          <div class="pattern-top">
            <strong>${escapeHtml(pattern.label)}</strong>
            <span class="pill ${pattern.category === "secret" ? "secret" : "pii"}">${escapeHtml(pattern.category)}</span>
          </div>
          <code>/${escapeHtml(pattern.pattern)}/${escapeHtml(pattern.flags || "g")}</code>
          ${pattern.placeholder ? `<p class="meta">Placeholder: ${escapeHtml(pattern.placeholder)}</p>` : ""}
          ${pattern.explanation ? `<p class="meta">${escapeHtml(pattern.explanation)}</p>` : ""}
          <div class="pattern-actions">
            <button type="button" class="pattern-action" data-pattern-action="toggle" data-pattern-id="${pattern.id}">${pattern.enabled ? "Disable" : "Enable"}</button>
            <button type="button" class="pattern-action is-danger" data-pattern-action="remove" data-pattern-id="${pattern.id}">Remove</button>
          </div>
        </article>
      `
    )
    .join("");
}

function renderRulePacks() {
  if (!settings.importedRulePacks.length) {
    importedRulePacks.innerHTML = `<div class="empty-state">No rule packs imported yet. Use the starter pack or bring your own JSON.</div>`;
    return;
  }

  importedRulePacks.innerHTML = settings.importedRulePacks
    .map(
      (pack) => `
        <article class="pattern-card">
          <div class="pattern-top">
            <strong>${escapeHtml(pack.name)}</strong>
            <span class="pill neutral">${pack.patternCount} rules</span>
          </div>
          <p class="meta">${escapeHtml(pack.description)}</p>
          <p class="meta">Imported ${escapeHtml(formatTimestamp(pack.importedAt))}</p>
        </article>
      `
    )
    .join("");
}

function renderTestLab() {
  testLabModes.innerHTML = (["placeholder", "partial-mask", "full-redact"] as RedactionMode[])
    .map(
      (mode) => `
        <button type="button" class="micro-button ${testLabMode === mode ? "is-active" : ""}" data-lab-mode="${mode}">
          ${escapeHtml(redactionModeLabel(mode))}
        </button>
      `
    )
    .join("");

  const source = testLabInput.value.trim();

  if (!source) {
    testLabOutput.innerHTML = `<div class="empty-state">Paste some text into the lab to preview detections and rewrites.</div>`;
    return;
  }

  const result = detectSensitiveContent(source, settings, {
    hostname: diagnostics?.hostname,
    origin: "test-lab",
    ignoreAllowRules: true,
    strictness: diagnostics?.profile?.strictness ?? "balanced"
  });

  if (!result.findings.length) {
    testLabOutput.innerHTML = `<div class="lab-output"><h3>No findings</h3><p class="meta">Nothing in this sample crossed the current confidence threshold.</p></div>`;
    return;
  }

  testLabOutput.innerHTML = `
    <div class="lab-output">
      <h3>${result.summary.total} finding${result.summary.total === 1 ? "" : "s"} in the test lab</h3>
      <p class="meta">${result.summary.secrets} secrets, ${result.summary.pii} pii, ${result.summary.highConfidence} high-confidence matches</p>
      <div class="lab-preview">${buildReplacementPreviewHtml(source, result.findings, testLabMode)}</div>
      <div class="pattern-list" style="margin-top: 10px;">
        ${result.findings
          .slice(0, 6)
          .map(
            (finding) => `
              <article class="pattern-card">
                <div class="pattern-top">
                  <strong>${escapeHtml(finding.label)}</strong>
                  <span class="pill ${finding.category === "secret" ? "secret" : "pii"}">${finding.confidence}%</span>
                </div>
                <p class="meta">${escapeHtml(finding.explanation)}</p>
                <p class="meta">${escapeHtml(finding.why.join(" "))}</p>
              </article>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderDiagnostics() {
  if (!diagnostics) {
    diagnosticsPanel.innerHTML = `<div class="empty-state" style="grid-column: 1 / -1;">${escapeHtml(diagnosticsStatus)}</div>`;
    return;
  }

  diagnosticsPanel.innerHTML = `
    <article class="diagnostic-card">
      <strong>Current site</strong>
      <p>${escapeHtml(diagnostics.siteLabel ?? diagnostics.hostname)}</p>
      <div class="diagnostic-pills">
        <span class="pill neutral">${escapeHtml(diagnostics.profile?.strictness ?? "n/a")}</span>
      </div>
    </article>
    <article class="diagnostic-card">
      <strong>Composer</strong>
      <p>${diagnostics.composerFound ? "Detected" : "Missing"}</p>
      <div class="diagnostic-pills">
        <span class="pill neutral">${diagnostics.sendButtonFound ? "Send button found" : "Send button missing"}</span>
      </div>
    </article>
    <article class="diagnostic-card">
      <strong>Attachment flags</strong>
      <p>${diagnostics.pendingAttachmentFlags} pending</p>
      <div class="diagnostic-pills">
        <span class="pill neutral">${diagnostics.profile?.scanAttachments ? "File scanning on" : "File scanning off"}</span>
      </div>
    </article>
    <article class="diagnostic-card">
      <strong>Last inline scan</strong>
      <p>${escapeHtml(diagnostics.lastInlineScan ? `${diagnostics.lastInlineScan.type} · ${diagnostics.lastInlineScan.total}` : "No scan yet")}</p>
      <div class="diagnostic-pills">
        <span class="pill neutral">${escapeHtml(diagnostics.lastInlineScan ? formatTimestamp(diagnostics.lastInlineScan.at) : diagnosticsStatus)}</span>
      </div>
    </article>
  `;
}

function renderLogs() {
  if (!logs.length) {
    logList.innerHTML = `<div class="empty-state">No flagged sends yet. When PromptProtect catches something, the summary appears here.</div>`;
    return;
  }

  logList.innerHTML = logs
    .slice(0, 6)
    .map(
      (entry) => `
        <article class="log-card">
          <div class="log-top">
            <strong>${escapeHtml(entry.siteLabel)}</strong>
            <span class="pill ${entry.action === "redacted" || entry.action === "safe_rewrite" || entry.action === "masked" ? "neutral" : "pii"}">${escapeHtml(entry.action)}</span>
          </div>
          <p class="meta">${escapeHtml(entry.hostname)} - ${escapeHtml(formatTimestamp(entry.timestamp))}</p>
          <div class="log-pills">
            <span class="pill secret">${entry.secrets} secrets</span>
            <span class="pill pii">${entry.pii} pii</span>
            <span class="pill neutral">${entry.totalFindings} total</span>
            <span class="pill neutral">${escapeHtml(entry.trigger)}</span>
          </div>
          ${entry.note ? `<p class="meta" style="margin-top: 8px;">${escapeHtml(entry.note)}</p>` : ""}
        </article>
      `
    )
    .join("");
}
