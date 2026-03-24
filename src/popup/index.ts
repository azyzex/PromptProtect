import { STORAGE_KEYS } from "../shared/defaults";
import { runtimeApi } from "../shared/runtime";
import { SUPPORTED_SITES } from "../shared/sites";
import type { CustomPattern, LogEntry, PromptProtectSettings } from "../shared/types";

const masterToggle = document.getElementById("master-toggle") as HTMLButtonElement;
const heroStats = document.getElementById("hero-stats") as HTMLDivElement;
const guardrailCaption = document.getElementById("guardrail-caption") as HTMLSpanElement;
const activityCaption = document.getElementById("activity-caption") as HTMLSpanElement;
const controlGrid = document.getElementById("control-grid") as HTMLDivElement;
const siteGrid = document.getElementById("site-grid") as HTMLDivElement;
const customPatternList = document.getElementById("custom-pattern-list") as HTMLDivElement;
const logList = document.getElementById("log-list") as HTMLDivElement;
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
  masterToggle.addEventListener("click", async () => {
    await saveSettings({ enabled: !settings.enabled });
  });

  controlGrid.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const card = target.closest<HTMLElement>("[data-control]");

    if (!card) {
      return;
    }

    const control = card.dataset.control;

    if (control === "detectSecrets") {
      await saveSettings({ detectSecrets: !settings.detectSecrets });
      return;
    }

    if (control === "detectPII") {
      await saveSettings({ detectPII: !settings.detectPII });
    }
  });

  siteGrid.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const button = target.closest<HTMLButtonElement>("[data-hostname]");

    if (!button) {
      return;
    }

    const hostname = button.dataset.hostname;

    if (!hostname) {
      return;
    }

    const nextAllowed = new Set(settings.allowedHostnames);

    if (nextAllowed.has(hostname)) {
      nextAllowed.delete(hostname);
    } else {
      nextAllowed.add(hostname);
    }

    await saveSettings({ allowedHostnames: Array.from(nextAllowed) });
  });

  customPatternList.addEventListener("click", async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const actionButton = target.closest<HTMLButtonElement>("[data-pattern-action]");

    if (!actionButton) {
      return;
    }

    const patternId = actionButton.dataset.patternId;

    if (!patternId) {
      return;
    }

    const action = actionButton.dataset.patternAction;

    if (action === "toggle") {
      const nextPatterns = settings.customPatterns.map((pattern) =>
        pattern.id === patternId ? { ...pattern, enabled: !pattern.enabled } : pattern
      );
      await saveSettings({ customPatterns: nextPatterns });
      return;
    }

    if (action === "remove") {
      const nextPatterns = settings.customPatterns.filter((pattern) => pattern.id !== patternId);
      await saveSettings({ customPatterns: nextPatterns });
    }
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
      enabled: true
    };

    await saveSettings({
      customPatterns: [...settings.customPatterns, nextPattern]
    });

    customRuleForm.reset();
    (document.getElementById("rule-flags") as HTMLInputElement).value = "g";
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
  renderHero();
  renderControls();
  renderSites();
  renderCustomPatterns();
  renderLogs();
}

function renderHero() {
  masterToggle.classList.toggle("is-off", !settings.enabled);
  masterToggle.textContent = settings.enabled ? "Shield On" : "Shield Off";

  heroStats.innerHTML = `
    ${renderStatCard("Protected sites", String(settings.allowedHostnames.length))}
    ${renderStatCard("Custom rules", String(settings.customPatterns.length))}
    ${renderStatCard("Flagged sends", String(logs.length))}
  `;

  guardrailCaption.textContent = settings.enabled ? "Local blocking active" : "Blocking paused";
  activityCaption.textContent = "Counts and rule labels only";
}

function renderStatCard(label: string, value: string): string {
  return `
    <article class="stat-card">
      <span class="small-note">${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </article>
  `;
}

function renderControls() {
  controlGrid.innerHTML = [
    renderControlCard({
      key: "detectSecrets",
      eyebrow: "Secrets",
      title: "Token and key detection",
      description: "OpenAI keys, GitHub tokens, JWTs, AWS IDs, and PEM blocks.",
      active: settings.detectSecrets,
      tone: "secret"
    }),
    renderControlCard({
      key: "detectPII",
      eyebrow: "PII",
      title: "Identity spill protection",
      description: "Email addresses and phone numbers get reviewed before send.",
      active: settings.detectPII,
      tone: "pii"
    })
  ].join("");
}

function renderControlCard(input: {
  key: "detectSecrets" | "detectPII";
  eyebrow: string;
  title: string;
  description: string;
  active: boolean;
  tone: "secret" | "pii";
}): string {
  return `
    <button type="button" class="toggle-card ${input.active ? "is-active" : ""} is-${input.tone}" data-control="${input.key}">
      <span class="toggle-card__eyebrow">${escapeHtml(input.eyebrow)}</span>
      <strong>${escapeHtml(input.title)}</strong>
      <p>${escapeHtml(input.description)}</p>
      <span class="toggle-card__state">${input.active ? "Enabled" : "Disabled"}</span>
    </button>
  `;
}

function renderSites() {
  siteGrid.innerHTML = SUPPORTED_SITES.flatMap((site) =>
    site.hostnames.map((hostname) => {
      const isActive = settings.allowedHostnames.includes(hostname);

      return `
        <button type="button" class="site-pill ${isActive ? "is-active" : ""}" data-hostname="${hostname}">
          <div class="site-meta">
            <div>
              <strong>${escapeHtml(site.label)}</strong>
              <span>${escapeHtml(hostname)}</span>
            </div>
            <span class="site-status">${isActive ? "Watching" : "Paused"}</span>
          </div>
        </button>
      `;
    })
  ).join("");
}

function renderCustomPatterns() {
  if (!settings.customPatterns.length) {
    customPatternList.innerHTML = `<div class="empty-state">No custom rules yet. Add one above for your own internal token formats.</div>`;
    return;
  }

  customPatternList.innerHTML = settings.customPatterns
    .map((pattern) => {
      const categoryClass = pattern.category === "secret" ? "secret" : "pii";

      return `
        <article class="pattern-card">
          <div class="pattern-top">
            <strong>${escapeHtml(pattern.label)}</strong>
            <span class="pill ${categoryClass}">${escapeHtml(pattern.category)}</span>
          </div>
          <code>/${escapeHtml(pattern.pattern)}/${escapeHtml(pattern.flags || "g")}</code>
          <div class="pattern-actions">
            <button type="button" class="pattern-action" data-pattern-action="toggle" data-pattern-id="${pattern.id}">
              ${pattern.enabled ? "Disable" : "Enable"}
            </button>
            <button type="button" class="pattern-action is-danger" data-pattern-action="remove" data-pattern-id="${pattern.id}">
              Remove
            </button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderLogs() {
  if (!logs.length) {
    logList.innerHTML = `<div class="empty-state">No flagged sends yet. When PromptProtect catches something, the summary appears here.</div>`;
    return;
  }

  logList.innerHTML = logs
    .slice(0, 4)
    .map(
      (entry) => `
        <article class="log-card">
          <div class="log-top">
            <strong>${escapeHtml(entry.siteLabel)}</strong>
            <span class="pill ${entry.action === "redacted" ? "neutral" : "pii"}">${escapeHtml(entry.action)}</span>
          </div>
          <p class="meta">${escapeHtml(entry.hostname)} - ${escapeHtml(formatTimestamp(entry.timestamp))}</p>
          <div class="log-pills">
            <span class="pill secret">${entry.secrets} secrets</span>
            <span class="pill pii">${entry.pii} pii</span>
            <span class="pill neutral">${entry.totalFindings} total</span>
          </div>
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
