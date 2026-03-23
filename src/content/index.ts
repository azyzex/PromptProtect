import { STORAGE_KEYS } from "../shared/defaults";
import { detectSensitiveContent } from "../shared/detector";
import { buildHighlightedHtml, maskSnippet, redactText } from "../shared/redaction";
import { runtimeApi } from "../shared/runtime";
import { getComposerSelectorsForHostname, getSendButtonSelectorsForHostname, getSupportedSiteForHostname } from "../shared/sites";
import type { AppendLogPayload, DetectionResult, PromptProtectSettings } from "../shared/types";

type ComposerElement = HTMLTextAreaElement | HTMLInputElement | HTMLElement;
type SubmissionTrigger = "keyboard" | "click";

const MODAL_ROOT_ID = "promptprotect-modal-root";

let settingsCache: PromptProtectSettings | null = null;
let modalOpen = false;
let allowNextSubmission = false;

void bootstrap();

async function bootstrap() {
  if (!getSupportedSiteForHostname(window.location.hostname)) {
    return;
  }

  settingsCache = await runtimeApi.getSettings().catch(() => null);

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes[STORAGE_KEYS.settings]?.newValue) {
      settingsCache = changes[STORAGE_KEYS.settings].newValue as PromptProtectSettings;
    }
  });

  document.addEventListener("keydown", handleKeydown, true);
  document.addEventListener("click", handleClick, true);
}

async function getSettings(): Promise<PromptProtectSettings | null> {
  if (settingsCache) {
    return settingsCache;
  }

  settingsCache = await runtimeApi.getSettings().catch(() => null);
  return settingsCache;
}

function isGuardEnabled(settings: PromptProtectSettings | null): settings is PromptProtectSettings {
  return Boolean(settings?.enabled && settings.allowedHostnames.includes(window.location.hostname));
}

async function handleKeydown(event: KeyboardEvent) {
  if (allowNextSubmission) {
    allowNextSubmission = false;
    return;
  }

  if (modalOpen || event.defaultPrevented || event.isComposing) {
    return;
  }

  if (event.key !== "Enter" || event.shiftKey || event.altKey || event.ctrlKey || event.metaKey) {
    return;
  }

  const composer = resolveComposer(event.target);

  if (!composer) {
    return;
  }

  await inspectSubmission({
    trigger: "keyboard",
    composer,
    sendButton: findNearestSendButton(composer),
    event
  });
}

async function handleClick(event: MouseEvent) {
  if (allowNextSubmission) {
    allowNextSubmission = false;
    return;
  }

  if (modalOpen || event.defaultPrevented) {
    return;
  }

  const sendButton = resolveSendButton(event.target);

  if (!sendButton) {
    return;
  }

  const composer = resolveComposer(document.activeElement) ?? findPreferredComposer();

  if (!composer) {
    return;
  }

  await inspectSubmission({
    trigger: "click",
    composer,
    sendButton,
    event
  });
}

async function inspectSubmission(context: {
  trigger: SubmissionTrigger;
  composer: ComposerElement;
  sendButton: HTMLElement | null;
  event: Event;
}) {
  const settings = await getSettings();

  if (!isGuardEnabled(settings)) {
    return;
  }

  const rawText = readComposerText(context.composer);

  if (!rawText.trim()) {
    return;
  }

  const result = detectSensitiveContent(rawText, settings);

  if (!result.findings.length) {
    return;
  }

  context.event.preventDefault();
  context.event.stopPropagation();
  context.event.stopImmediatePropagation();

  modalOpen = true;

  try {
    const outcome = await openReviewModal(rawText, result);

    if (outcome === "cancel") {
      await logFinding("cancelled", result);
      focusComposer(context.composer);
      return;
    }

    const redacted = redactText(rawText, result.findings);
    writeComposerText(context.composer, redacted.text);
    await logFinding("redacted", result);
    await wait(80);
    await submitAfterRedaction(context.composer, context.sendButton, context.trigger);
  } finally {
    modalOpen = false;
  }
}

async function logFinding(action: AppendLogPayload["action"], result: DetectionResult) {
  const site = getSupportedSiteForHostname(window.location.hostname);

  await runtimeApi.appendLog({
    hostname: window.location.hostname,
    siteLabel: site?.label ?? window.location.hostname,
    action,
    totalFindings: result.summary.total,
    secrets: result.summary.secrets,
    pii: result.summary.pii,
    ruleLabels: result.summary.ruleLabels
  });
}

function resolveComposer(target: EventTarget | Element | null): ComposerElement | null {
  if (target instanceof Element) {
    const selectors = getComposerSelectorsForHostname(window.location.hostname);

    for (const selector of selectors) {
      const candidate = target.closest(selector);

      if (candidate instanceof HTMLElement && isVisible(candidate) && !isPromptProtectNode(candidate)) {
        return candidate as ComposerElement;
      }
    }
  }

  const activeElement = document.activeElement;

  if (activeElement instanceof HTMLElement && isComposerCandidate(activeElement)) {
    return activeElement as ComposerElement;
  }

  return findPreferredComposer();
}

function findPreferredComposer(): ComposerElement | null {
  const selectors = getComposerSelectorsForHostname(window.location.hostname);
  const candidates = selectors.flatMap((selector) => Array.from(document.querySelectorAll<HTMLElement>(selector)));
  const visible = uniqueElements(candidates).filter((candidate) => isComposerCandidate(candidate));

  visible.sort((left, right) => {
    const leftRect = left.getBoundingClientRect();
    const rightRect = right.getBoundingClientRect();
    return rightRect.bottom - leftRect.bottom || rightRect.width * rightRect.height - leftRect.width * leftRect.height;
  });

  return (visible[0] as ComposerElement | undefined) ?? null;
}

function isComposerCandidate(element: HTMLElement): boolean {
  if (!isVisible(element) || isPromptProtectNode(element)) {
    return false;
  }

  return element.matches(getComposerSelectorsForHostname(window.location.hostname).join(", "));
}

function resolveSendButton(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof Element)) {
    return null;
  }

  const selectors = getSendButtonSelectorsForHostname(window.location.hostname);

  for (const selector of selectors) {
    const candidate = target.closest(selector);

    if (candidate instanceof HTMLElement && isVisible(candidate) && !candidate.hasAttribute("disabled") && !isPromptProtectNode(candidate)) {
      return candidate;
    }
  }

  return null;
}

function findNearestSendButton(composer: HTMLElement): HTMLElement | null {
  const selectors = getSendButtonSelectorsForHostname(window.location.hostname);
  const candidates = selectors.flatMap((selector) => Array.from(document.querySelectorAll<HTMLElement>(selector)));
  const visible = uniqueElements(candidates).filter(
    (candidate) => isVisible(candidate) && !candidate.hasAttribute("disabled") && !isPromptProtectNode(candidate)
  );

  if (!visible.length) {
    return null;
  }

  const composerRect = composer.getBoundingClientRect();

  visible.sort((left, right) => {
    const leftDistance = distanceToComposer(left.getBoundingClientRect(), composerRect);
    const rightDistance = distanceToComposer(right.getBoundingClientRect(), composerRect);
    return leftDistance - rightDistance;
  });

  return visible[0] ?? null;
}

function distanceToComposer(buttonRect: DOMRect, composerRect: DOMRect): number {
  const horizontal = Math.abs(buttonRect.left - composerRect.right);
  const vertical = Math.abs(buttonRect.top - composerRect.top);
  return horizontal + vertical;
}

function uniqueElements<T>(elements: T[]): T[] {
  return Array.from(new Set(elements));
}

function isVisible(element: HTMLElement): boolean {
  const styles = window.getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  return styles.visibility !== "hidden" && styles.display !== "none" && rect.width > 0 && rect.height > 0;
}

function isPromptProtectNode(element: HTMLElement): boolean {
  return Boolean(element.closest(`#${MODAL_ROOT_ID}`));
}

function readComposerText(composer: ComposerElement): string {
  if (composer instanceof HTMLTextAreaElement || composer instanceof HTMLInputElement) {
    return composer.value;
  }

  return composer.innerText.replace(/\u00a0/g, " ");
}

function focusComposer(composer: ComposerElement) {
  if (composer instanceof HTMLElement) {
    composer.focus();
  }
}

function writeComposerText(composer: ComposerElement, text: string) {
  if (composer instanceof HTMLTextAreaElement || composer instanceof HTMLInputElement) {
    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(composer), "value");

    if (descriptor?.set) {
      descriptor.set.call(composer, text);
    } else {
      composer.value = text;
    }

    composer.dispatchEvent(new Event("input", { bubbles: true }));
    composer.dispatchEvent(new Event("change", { bubbles: true }));
    return;
  }

  composer.focus();
  const selection = window.getSelection();

  if (selection) {
    const range = document.createRange();
    range.selectNodeContents(composer);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  const inserted = typeof document.execCommand === "function" ? document.execCommand("insertText", false, text) : false;

  if (!inserted) {
    composer.replaceChildren(...textToNodes(text));
  }

  composer.dispatchEvent(
    new InputEvent("input", {
      bubbles: true,
      inputType: "insertText",
      data: text
    })
  );
}

function textToNodes(value: string): Node[] {
  const lines = value.split("\n");
  const nodes: Node[] = [];

  lines.forEach((line, index) => {
    if (index > 0) {
      nodes.push(document.createElement("br"));
    }

    nodes.push(document.createTextNode(line));
  });

  return nodes;
}

async function submitAfterRedaction(composer: ComposerElement, sendButton: HTMLElement | null, trigger: SubmissionTrigger) {
  focusComposer(composer);
  await wait(32);
  allowNextSubmission = true;

  const fallbackComposer = composer instanceof HTMLElement ? composer : null;
  const button = sendButton && document.contains(sendButton) ? sendButton : fallbackComposer ? findNearestSendButton(fallbackComposer) : null;

  if (button) {
    button.click();
    return;
  }

  if (trigger === "keyboard" && composer instanceof HTMLElement) {
    composer.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        bubbles: true,
        cancelable: true
      })
    );
  }
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function openReviewModal(text: string, result: DetectionResult): Promise<"redact" | "cancel"> {
  const host = document.createElement("div");
  host.id = MODAL_ROOT_ID;
  const shadowRoot = host.attachShadow({ mode: "open" });
  document.documentElement.appendChild(host);

  const site = getSupportedSiteForHostname(window.location.hostname);
  const findingsHtml = result.findings
    .map(
      (finding) => `
        <li class="pp-finding">
          <div class="pp-finding__top">
            <span class="pp-badge pp-badge--${finding.category}">${finding.label}</span>
            <span class="pp-finding__source">${finding.source === "custom" ? "Custom rule" : "Built-in rule"}</span>
          </div>
          <code class="pp-finding__snippet">${maskSnippet(finding.match)}</code>
        </li>
      `
    )
    .join("");

  shadowRoot.innerHTML = `
    <style>${modalStyles}</style>
    <div class="pp-overlay" role="presentation">
      <div class="pp-dialog" role="dialog" aria-modal="true" aria-labelledby="pp-title">
        <p class="pp-eyebrow">PromptProtect</p>
        <h2 id="pp-title">Sensitive content detected before send</h2>
        <p class="pp-copy">
          ${result.summary.total} finding${result.summary.total === 1 ? "" : "s"} matched in ${site?.label ?? window.location.hostname}. Nothing is stored unless you proceed with redaction.
        </p>

        <div class="pp-summary">
          <span class="pp-pill pp-pill--secret">${result.summary.secrets} secret${result.summary.secrets === 1 ? "" : "s"}</span>
          <span class="pp-pill pp-pill--pii">${result.summary.pii} pii</span>
        </div>

        <div class="pp-preview">
          ${buildHighlightedHtml(text, result.findings)}
        </div>

        <div class="pp-findings">
          <div class="pp-section-title">Matched rules</div>
          <ul class="pp-finding-list">${findingsHtml}</ul>
        </div>

        <div class="pp-actions">
          <button type="button" id="pp-cancel" class="pp-button pp-button--ghost">Cancel</button>
          <button type="button" id="pp-redact" class="pp-button pp-button--primary">Redact &amp; Send</button>
        </div>
      </div>
    </div>
  `;

  const cancelButton = shadowRoot.getElementById("pp-cancel") as HTMLButtonElement | null;
  const redactButton = shadowRoot.getElementById("pp-redact") as HTMLButtonElement | null;
  const overlay = shadowRoot.querySelector(".pp-overlay");

  cancelButton?.focus();

  return new Promise((resolve) => {
    const onWindowKeydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        cleanup("cancel");
      }
    };

    const cleanup = (value: "redact" | "cancel") => {
      window.removeEventListener("keydown", onWindowKeydown, true);
      host.remove();
      resolve(value);
    };

    cancelButton?.addEventListener("click", () => cleanup("cancel"), { once: true });
    redactButton?.addEventListener("click", () => cleanup("redact"), { once: true });
    overlay?.addEventListener("click", (event) => {
      if (event.target === overlay) {
        cleanup("cancel");
      }
    });
    window.addEventListener("keydown", onWindowKeydown, true);
  });
}

const modalStyles = `
  :host {
    all: initial;
  }

  * {
    box-sizing: border-box;
    font-family: "Segoe UI", "SF Pro Text", system-ui, sans-serif;
  }

  .pp-overlay {
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    display: grid;
    place-items: center;
    background: rgba(15, 23, 42, 0.56);
    padding: 20px;
  }

  .pp-dialog {
    width: min(760px, 100%);
    max-height: min(88vh, 860px);
    overflow: auto;
    border-radius: 24px;
    background:
      radial-gradient(circle at top right, rgba(234, 88, 12, 0.12), transparent 30%),
      linear-gradient(180deg, #fffdf9 0%, #fff7ed 100%);
    color: #1f2937;
    border: 1px solid rgba(31, 41, 55, 0.14);
    box-shadow: 0 28px 80px rgba(15, 23, 42, 0.32);
    padding: 24px;
  }

  .pp-eyebrow {
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-size: 12px;
    color: #9a3412;
  }

  #pp-title {
    margin: 8px 0;
    font-size: 28px;
    line-height: 1.1;
  }

  .pp-copy {
    margin: 0 0 18px;
    color: #57534e;
    line-height: 1.5;
  }

  .pp-summary,
  .pp-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
  }

  .pp-summary {
    margin-bottom: 18px;
  }

  .pp-pill,
  .pp-badge {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 6px 11px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .pp-pill--secret,
  .pp-badge--secret {
    background: rgba(180, 35, 24, 0.12);
    color: #b42318;
  }

  .pp-pill--pii,
  .pp-badge--pii {
    background: rgba(194, 65, 12, 0.14);
    color: #c2410c;
  }

  .pp-preview {
    border-radius: 18px;
    border: 1px solid rgba(31, 41, 55, 0.12);
    background: rgba(255, 255, 255, 0.88);
    padding: 16px;
    white-space: pre-wrap;
    line-height: 1.55;
    max-height: 280px;
    overflow: auto;
  }

  .pp-mark {
    padding: 1px 3px;
    border-radius: 6px;
    font-weight: 700;
  }

  .pp-mark--secret {
    background: rgba(180, 35, 24, 0.14);
    color: #7f1d1d;
  }

  .pp-mark--pii {
    background: rgba(194, 65, 12, 0.16);
    color: #9a3412;
  }

  .pp-findings {
    margin-top: 18px;
  }

  .pp-section-title {
    margin-bottom: 10px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #6b7280;
  }

  .pp-finding-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: grid;
    gap: 10px;
  }

  .pp-finding {
    border-radius: 16px;
    border: 1px solid rgba(31, 41, 55, 0.1);
    background: rgba(255, 255, 255, 0.82);
    padding: 12px;
  }

  .pp-finding__top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 8px;
  }

  .pp-finding__source {
    font-size: 12px;
    color: #78716c;
  }

  .pp-finding__snippet {
    display: block;
    white-space: pre-wrap;
    word-break: break-word;
    color: #111827;
  }

  .pp-actions {
    justify-content: flex-end;
    margin-top: 18px;
  }

  .pp-button {
    border: 0;
    border-radius: 999px;
    padding: 12px 18px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 700;
  }

  .pp-button--ghost {
    background: rgba(148, 163, 184, 0.14);
    color: #334155;
  }

  .pp-button--primary {
    background: linear-gradient(135deg, #ea580c, #b91c1c);
    color: white;
  }

  @media (max-width: 640px) {
    .pp-dialog {
      padding: 18px;
      border-radius: 20px;
    }

    #pp-title {
      font-size: 24px;
    }

    .pp-actions {
      justify-content: stretch;
    }

    .pp-button {
      width: 100%;
    }
  }
`;
