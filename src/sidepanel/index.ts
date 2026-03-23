import { STORAGE_KEYS } from "../shared/defaults";
import { runtimeApi } from "../shared/runtime";
import { SUPPORTED_SITES } from "../shared/sites";
import type { CustomPattern, LogEntry, PromptProtectSettings } from "../shared/types";

const enabledToggle = document.getElementById("enabled-toggle") as HTMLInputElement;
const detectSecretsToggle = document.getElementById("detect-secrets-toggle") as HTMLInputElement;
const detectPiiToggle = document.getElementById("detect-pii-toggle") as HTMLInputElement;
const siteList = document.getElementById("site-list") as HTMLDivElement;
const customPatternList = document.getElementById("custom-pattern-list") as HTMLDivElement;
const logList = document.getElementById("log-list") as HTMLDivElement;
const stats = document.getElementById("stats") as HTMLDivElement;
const clearLogsButton = document.getElementById("clear-logs-button") as HTMLButtonElement;
const customRuleForm = document.getElementById("custom-rule-form") as HTMLFormElement;
const formStatus = document.getElementById("form-status") as HTMLParagraphElement;

let settings: PromptProtectSettings;
let logs: LogEntry[] = [];

void init();

async function init() {
  const [loadedSettings, loadedLogs] = await Promise.all([runtimeApi.getSettings(), runtimeApi.getLogs()]);
  settings = loadedSettings;
  logs = loadedLogs;

  bindListeners();
  render();

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
  enabledToggle.addEventListener("change", async () => {
    await saveSettings({ enabled: enabledToggle.checked });
  });

  detectSecretsToggle.addEventListener("change", async () => {
    await saveSettings({ detectSecrets: detectSecretsToggle.checked });
  });

  detectPiiToggle.addEventListener("change", async () => {
    await saveSettings({ detectPII: detectPiiToggle.checked });
  });

  siteList.addEventListener("change", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLInputElement) || target.name !== "site-toggle") {
      return;
    }

    const nextAllowed = new Set(settings.allowedHostnames);

    if (target.checked) {
      nextAllowed.add(target.value);
    } else {
      nextAllowed.delete(target.value);
    }

    await saveSettings({ allowedHostnames: Array.from(nextAllowed) });
  });

  customPatternList.addEventListener("change", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLInputElement) || target.name !== "pattern-enabled") {
      return;
    }

    const nextPatterns = settings.customPatterns.map((pattern) =>
      pattern.id === target.value ? { ...pattern, enabled: target.checked } : pattern
    );

    await saveSettings({ customPatterns: nextPatterns });
  });

  customPatternList.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const removeButton = target.closest<HTMLButtonElement>("button[data-remove-id]");

    if (!removeButton) {
      return;
    }

    const nextPatterns = settings.customPatterns.filter((pattern) => pattern.id !== removeButton.dataset.removeId);
    await saveSettings({ customPatterns: nextPatterns });
  });

  clearLogsButton.addEventListener("click", async () => {
    logs = await runtimeApi.clearLogs();
    render();
  });

  customRuleForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    formStatus.textContent = "";

    const formData = new FormData(customRuleForm);
    const label = String(formData.get("label") ?? "").trim();
    const pattern = String(formData.get("pattern") ?? "").trim();
    const category = String(formData.get("category") ?? "secret");
    const flags = normalizeFlags(String(formData.get("flags") ?? "g"));

    if (!label || !pattern || (category !== "secret" && category !== "pii")) {
      formStatus.textContent = "Fill in a label, regex pattern, and category.";
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
      enabled: true
    };

    await saveSettings({
      customPatterns: [...settings.customPatterns, nextPattern]
    });

    customRuleForm.reset();
    const flagsInput = document.getElementById("rule-flags") as HTMLInputElement;
    flagsInput.value = "g";
    formStatus.textContent = "Custom rule added.";
  });
}

function normalizeFlags(flags: string): string {
  return Array.from(new Set(flags.replace(/[^dgimsuy]/g, "").split(""))).join("");
}

function ensureGlobal(flags: string): string {
  return flags.includes("g") ? flags : `${flags}g`;
}

async function saveSettings(partial: Partial<PromptProtectSettings>) {
  settings = await runtimeApi.saveSettings({
    ...settings,
    ...partial
  });
  render();
}

function render() {
  enabledToggle.checked = settings.enabled;
  detectSecretsToggle.checked = settings.detectSecrets;
  detectPiiToggle.checked = settings.detectPII;

  renderStats();
  renderSites();
  renderCustomPatterns();
  renderLogs();
}

function renderStats() {
  const activeSites = settings.allowedHostnames.length;
  const customRules = settings.customPatterns.length;

  stats.innerHTML = `
    <article class="stat-card">
      <span class="meta">Blocking</span>
      <strong>${settings.enabled ? "On" : "Off"}</strong>
    </article>
    <article class="stat-card">
      <span class="meta">Active Sites</span>
      <strong>${activeSites}</strong>
    </article>
    <article class="stat-card">
      <span class="meta">Custom Rules</span>
      <strong>${customRules}</strong>
    </article>
    <article class="stat-card">
      <span class="meta">Flagged Events</span>
      <strong>${logs.length}</strong>
    </article>
  `;
}

function renderSites() {
  siteList.innerHTML = SUPPORTED_SITES.flatMap((site) =>
    site.hostnames.map(
      (hostname) => `
        <label class="site-toggle">
          <input type="checkbox" name="site-toggle" value="${hostname}" ${settings.allowedHostnames.includes(hostname) ? "checked" : ""} />
          <span>
            <strong>${site.label}</strong>
            <span>${hostname}</span>
          </span>
        </label>
      `
    )
  ).join("");
}

function renderCustomPatterns() {
  if (!settings.customPatterns.length) {
    customPatternList.innerHTML = `<div class="empty">No custom rules yet. Add one above to cover your own token formats.</div>`;
    return;
  }

  customPatternList.innerHTML = settings.customPatterns
    .map(
      (pattern) => `
        <article class="row-card">
          <div class="row-top">
            <div>
              <strong>${escapeHtml(pattern.label)}</strong>
              <div class="meta">${pattern.category} • /${escapeHtml(pattern.pattern)}/${escapeHtml(pattern.flags || "g")}</div>
            </div>
            <span class="tag ${pattern.category === "secret" ? "tag-danger" : "tag-warn"}">${pattern.category}</span>
          </div>

          <div class="row-actions">
            <label class="toggle">
              <input type="checkbox" name="pattern-enabled" value="${pattern.id}" ${pattern.enabled ? "checked" : ""} />
              <span>Enabled</span>
            </label>
            <button type="button" class="button button-danger" data-remove-id="${pattern.id}">Remove</button>
          </div>
        </article>
      `
    )
    .join("");
}

function renderLogs() {
  if (!logs.length) {
    logList.innerHTML = `<div class="empty">No flagged events yet. Trigger a detection on a supported site to see history here.</div>`;
    return;
  }

  logList.innerHTML = logs
    .map(
      (entry) => `
        <article class="log-card">
          <div class="log-top">
            <div>
              <strong>${escapeHtml(entry.siteLabel)}</strong>
              <div class="meta">${escapeHtml(entry.hostname)} • ${formatTimestamp(entry.timestamp)}</div>
            </div>
            <span class="tag ${entry.action === "redacted" ? "" : "tag-warn"}">${entry.action}</span>
          </div>

          <div class="pill-row" style="margin-top: 12px;">
            <span class="tag tag-danger">${entry.secrets} secrets</span>
            <span class="tag tag-warn">${entry.pii} pii</span>
            <span class="tag">${entry.totalFindings} total</span>
          </div>

          <p class="meta" style="margin: 12px 0 0;">
            ${entry.ruleLabels.length ? escapeHtml(entry.ruleLabels.join(", ")) : "No rule labels recorded"}
          </p>
        </article>
      `
    )
    .join("");
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
