import { buildHighlightedHtml, buildReplacementPreviewHtml, maskSnippet, redactionModeLabel } from "../shared/redaction";
import type { AttachmentFinding, DetectionFinding, RedactionMode } from "../shared/types";

export type ReviewDecision =
  | { type: "cancel" }
  | { type: "ignore-once" }
  | { type: "allowlisted-send" }
  | { type: "rewrite"; mode: RedactionMode };

interface ReviewModalInput {
  hostId: string;
  siteLabel: string;
  originalText: string;
  composerFindings: DetectionFinding[];
  attachmentFindings: AttachmentFinding[];
  defaultMode: RedactionMode;
  onAllowComposer: (finding: DetectionFinding) => Promise<void>;
  onAllowAttachment: (finding: AttachmentFinding) => Promise<void>;
  onAllowComposerTemporarily: (finding: DetectionFinding, minutes: number) => Promise<void>;
  onAllowAttachmentTemporarily: (finding: AttachmentFinding, minutes: number) => Promise<void>;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export async function openReviewModal(input: ReviewModalInput): Promise<ReviewDecision> {
  const host = document.createElement("div");
  host.id = input.hostId;
  const shadowRoot = host.attachShadow({ mode: "open" });
  document.documentElement.appendChild(host);

  let composerFindings = [...input.composerFindings];
  let attachmentFindings = [...input.attachmentFindings];
  let previewMode = input.defaultMode;
  let tempAllowTarget: { kind: "composer" | "attachment"; id: string } | null = null;
  let tempAllowMinutes = 60;

  function renderTempAllowPicker(kind: "composer" | "attachment", findingId: string): string {
    if (!tempAllowTarget || tempAllowTarget.kind !== kind || tempAllowTarget.id !== findingId) {
      return "";
    }

    const presets = [5, 15, 30, 60, 240, 1440];

    return `
      <div class="pp-temp-allow" data-temp-allow-kind="${kind}" data-temp-allow-id="${findingId}">
        <span class="pp-temp-allow__label">Allow for</span>
        <div class="pp-temp-allow__presets">
          ${presets
            .map(
              (minutes) =>
                `<button type="button" class="pp-mini-button pp-mini-button--ghost" data-temp-allow-preset="${minutes}" data-temp-allow-kind="${kind}" data-temp-allow-id="${findingId}">${minutes}m</button>`
            )
            .join("")}
        </div>
        <div class="pp-temp-allow__custom">
          <input
            class="pp-temp-allow__input"
            inputmode="numeric"
            pattern="[0-9]*"
            value="${tempAllowMinutes}"
            aria-label="Temporary allow duration in minutes"
            data-temp-allow-minutes-input="${findingId}"
          />
          <span class="pp-temp-allow__suffix">minutes</span>
        </div>
        <div class="pp-temp-allow__actions">
          <button type="button" class="pp-mini-button" data-temp-allow-confirm data-temp-allow-kind="${kind}" data-temp-allow-id="${findingId}">Confirm</button>
          <button type="button" class="pp-mini-button pp-mini-button--ghost" data-temp-allow-cancel data-temp-allow-kind="${kind}" data-temp-allow-id="${findingId}">Cancel</button>
        </div>
      </div>
    `;
  }

  function totalFindings(): number {
    return composerFindings.length + attachmentFindings.length;
  }

  function render() {
    const previousDialog = shadowRoot.querySelector<HTMLElement>(".pp-dialog");
    const previousScrollTop = previousDialog?.scrollTop ?? 0;
    const previousScrollLeft = previousDialog?.scrollLeft ?? 0;

    const total = totalFindings();
    const secretCount =
      composerFindings.filter((finding) => finding.category === "secret").length +
      attachmentFindings.filter((finding) => finding.category === "secret").length;
    const piiCount =
      composerFindings.filter((finding) => finding.category === "pii").length +
      attachmentFindings.filter((finding) => finding.category === "pii").length;

    const composerItems = composerFindings
      .map(
        (finding) => `
          <li class="pp-finding">
            <div class="pp-finding__top">
              <div class="pp-pill-row">
                <span class="pp-badge pp-badge--${finding.category}">${finding.label}</span>
                <span class="pp-badge pp-badge--neutral">${finding.severity}</span>
                <span class="pp-badge pp-badge--neutral">${finding.confidence}% confidence</span>
              </div>
              <div class="pp-allow-row">
                <button type="button" class="pp-mini-button" data-allow-composer="${finding.id}">Allow on this site</button>
                <button type="button" class="pp-mini-button pp-mini-button--ghost" data-temp-allow-composer="${finding.id}">Allow temporarily…</button>
              </div>
              ${renderTempAllowPicker("composer", finding.id)}
            </div>
            <code class="pp-finding__snippet">${escapeHtml(maskSnippet(finding.match))}</code>
            <p class="pp-finding__explanation">${escapeHtml(finding.explanation)}</p>
            <ul class="pp-why-list">${finding.why.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
          </li>
        `
      )
      .join("");

    const attachmentItems = attachmentFindings
      .map(
        (finding) => `
          <li class="pp-finding">
            <div class="pp-finding__top">
              <div class="pp-pill-row">
                <span class="pp-badge pp-badge--${finding.category}">${finding.label}</span>
                <span class="pp-badge pp-badge--neutral">${escapeHtml(finding.fileName)}</span>
                <span class="pp-badge pp-badge--neutral">${finding.confidence}% confidence</span>
              </div>
              <div class="pp-allow-row">
                <button type="button" class="pp-mini-button" data-allow-attachment="${finding.id}">Allow on this site</button>
                <button type="button" class="pp-mini-button pp-mini-button--ghost" data-temp-allow-attachment="${finding.id}">Allow temporarily…</button>
              </div>
              ${renderTempAllowPicker("attachment", finding.id)}
            </div>
            <code class="pp-finding__snippet">${escapeHtml(finding.matchPreview)}</code>
            <p class="pp-finding__explanation">${escapeHtml(finding.explanation)}</p>
            <ul class="pp-why-list">${finding.why.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
          </li>
        `
      )
      .join("");

    shadowRoot.innerHTML = `
      <style>${modalStyles}</style>
      <div class="pp-overlay" role="presentation">
        <div class="pp-dialog" role="dialog" aria-modal="true" aria-labelledby="pp-title">
          <div class="pp-hero">
            <div>
              <p class="pp-eyebrow">PromptProtect</p>
              <h2 id="pp-title">Sensitive content detected before send</h2>
              <p class="pp-copy">
                ${total} finding${total === 1 ? "" : "s"} matched in ${escapeHtml(input.siteLabel)}. Review the details, allow known-safe values, or rewrite the prompt before sending.
              </p>
            </div>
            <div class="pp-shield">Review</div>
          </div>

          <div class="pp-metrics">
            <article class="pp-metric">
              <span class="pp-metric__label">Secrets</span>
              <strong>${secretCount}</strong>
            </article>
            <article class="pp-metric">
              <span class="pp-metric__label">PII</span>
              <strong>${piiCount}</strong>
            </article>
            <article class="pp-metric">
              <span class="pp-metric__label">Attachments</span>
              <strong>${attachmentFindings.length}</strong>
            </article>
          </div>

          <div class="pp-block">
            <div class="pp-block__top">
              <span class="pp-section-title">Current Prompt</span>
              <span class="pp-inline-note">Highlighted ranges stay local to this page.</span>
            </div>
            <div class="pp-preview">${buildHighlightedHtml(input.originalText, composerFindings)}</div>
          </div>

          <div class="pp-block">
            <div class="pp-block__top">
              <span class="pp-section-title">Rewrite Preview</span>
              <div class="pp-mode-row">
                <button type="button" class="pp-mode-button ${previewMode === "placeholder" ? "is-active" : ""}" data-mode="placeholder">${redactionModeLabel("placeholder")}</button>
                <button type="button" class="pp-mode-button ${previewMode === "partial-mask" ? "is-active" : ""}" data-mode="partial-mask">${redactionModeLabel("partial-mask")}</button>
                <button type="button" class="pp-mode-button ${previewMode === "full-redact" ? "is-active" : ""}" data-mode="full-redact">${redactionModeLabel("full-redact")}</button>
              </div>
            </div>
            <div class="pp-preview pp-preview--replacement">
              ${
                composerFindings.length
                  ? buildReplacementPreviewHtml(input.originalText, composerFindings, previewMode)
                  : `<span class="pp-empty-note">No composer text remains to rewrite. Attachment findings can only be reviewed, not auto-redacted.</span>`
              }
            </div>
          </div>

          <div class="pp-block">
            <div class="pp-block__top">
              <span class="pp-section-title">Why Flagged</span>
              <span class="pp-inline-note">Use "Allow on this site" only for known-safe demo values.</span>
            </div>
            <ul class="pp-finding-list">
              ${totalFindings() > 0 ? `${composerItems}${attachmentItems}` : `<div class="pp-empty-note">Everything currently in this prompt is allowlisted for ${escapeHtml(input.siteLabel)}.</div>`}
            </ul>
          </div>

          <div class="pp-actions">
            <span class="pp-footer-note">
              ${attachmentFindings.length > 0 ? "Attachments cannot be auto-redacted. Sending after review keeps them unchanged." : "Cancel keeps the draft untouched."}
            </span>
            <button type="button" id="pp-cancel" class="pp-button pp-button--ghost">Cancel</button>
            <button type="button" id="pp-ignore" class="pp-button pp-button--ghost">${total === 0 ? "Send now" : "Ignore Once & Send"}</button>
            ${
              composerFindings.length
                ? `
                  <button type="button" class="pp-button pp-button--primary" data-send-mode="placeholder">Safe Rewrite &amp; Send</button>
                  <button type="button" class="pp-button pp-button--primary pp-button--secondary" data-send-mode="partial-mask">Mask &amp; Send</button>
                  <button type="button" class="pp-button pp-button--primary pp-button--secondary" data-send-mode="full-redact">Full Redact &amp; Send</button>
                `
                : ""
            }
          </div>
        </div>
      </div>
    `;

    const dialog = shadowRoot.querySelector<HTMLElement>(".pp-dialog");
    if (dialog) {
      dialog.scrollTop = previousScrollTop;
      dialog.scrollLeft = previousScrollLeft;
    }
  }

  render();

  return new Promise((resolve) => {
    const cleanup = (decision: ReviewDecision) => {
      window.removeEventListener("keydown", onWindowKeydown, true);
      host.remove();
      resolve(decision);
    };

    const onWindowKeydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        cleanup({ type: "cancel" });
      }
    };

    shadowRoot.addEventListener("click", async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      if (target.id === "pp-cancel") {
        cleanup({ type: "cancel" });
        return;
      }

      if (target.id === "pp-ignore") {
        cleanup({ type: totalFindings() === 0 ? "allowlisted-send" : "ignore-once" });
        return;
      }

      const overlay = target.closest(".pp-overlay");

      if (target === overlay) {
        cleanup({ type: "cancel" });
        return;
      }

      const sendButton = target.closest<HTMLElement>("[data-send-mode]");

      if (sendButton?.dataset.sendMode) {
        cleanup({ type: "rewrite", mode: sendButton.dataset.sendMode as RedactionMode });
        return;
      }

      const modeButton = target.closest<HTMLElement>("[data-mode]");

      if (modeButton?.dataset.mode) {
        previewMode = modeButton.dataset.mode as RedactionMode;
        render();
        return;
      }

      const tempAllowPresetButton = target.closest<HTMLElement>("[data-temp-allow-preset]");

      if (tempAllowPresetButton?.dataset.tempAllowPreset) {
        const minutes = Number.parseInt(tempAllowPresetButton.dataset.tempAllowPreset, 10);

        if (Number.isFinite(minutes) && minutes > 0) {
          tempAllowMinutes = minutes;
          render();
        }

        return;
      }

      const tempAllowCancelButton = target.closest<HTMLElement>("[data-temp-allow-cancel]");

      if (tempAllowCancelButton) {
        tempAllowTarget = null;
        tempAllowMinutes = 60;
        render();
        return;
      }

      const tempAllowConfirmButton = target.closest<HTMLElement>("[data-temp-allow-confirm]");

      if (tempAllowConfirmButton) {
        const kind = (tempAllowConfirmButton.dataset.tempAllowKind as "composer" | "attachment" | undefined) ?? undefined;
        const id = tempAllowConfirmButton.dataset.tempAllowId ?? null;

        if (!kind || !id) {
          return;
        }

        const minutesInput = shadowRoot.querySelector<HTMLInputElement>(`[data-temp-allow-minutes-input="${CSS.escape(id)}"]`);
        const minutesFromInput = minutesInput ? Number.parseInt(minutesInput.value.trim(), 10) : tempAllowMinutes;
        const minutes = Number.isFinite(minutesFromInput) ? minutesFromInput : tempAllowMinutes;

        if (!Number.isFinite(minutes) || minutes <= 0) {
          return;
        }

        if (kind === "composer") {
          const finding = composerFindings.find((item) => item.id === id);
          if (!finding) {
            return;
          }
          await input.onAllowComposerTemporarily(finding, minutes);
          composerFindings = composerFindings.filter((item) => item.id !== finding.id);
        } else {
          const finding = attachmentFindings.find((item) => item.id === id);
          if (!finding) {
            return;
          }
          await input.onAllowAttachmentTemporarily(finding, minutes);
          attachmentFindings = attachmentFindings.filter((item) => item.id !== finding.id);
        }

        tempAllowTarget = null;
        tempAllowMinutes = 60;
        render();
        return;
      }

      const composerAllowButton = target.closest<HTMLElement>("[data-allow-composer]");

      if (composerAllowButton?.dataset.allowComposer) {
        const finding = composerFindings.find((item) => item.id === composerAllowButton.dataset.allowComposer);

        if (!finding) {
          return;
        }

        await input.onAllowComposer(finding);
        composerFindings = composerFindings.filter((item) => item.id !== finding.id);
        render();
        return;
      }

      const composerTempAllowButton = target.closest<HTMLElement>("[data-temp-allow-composer]");

      if (composerTempAllowButton?.dataset.tempAllowComposer) {
        const finding = composerFindings.find((item) => item.id === composerTempAllowButton.dataset.tempAllowComposer);

        if (!finding) {
          return;
        }

        tempAllowTarget = { kind: "composer", id: finding.id };
        tempAllowMinutes = 60;
        render();
        return;
      }

      const attachmentAllowButton = target.closest<HTMLElement>("[data-allow-attachment]");

      if (attachmentAllowButton?.dataset.allowAttachment) {
        const finding = attachmentFindings.find((item) => item.id === attachmentAllowButton.dataset.allowAttachment);

        if (!finding) {
          return;
        }

        await input.onAllowAttachment(finding);
        attachmentFindings = attachmentFindings.filter((item) => item.id !== finding.id);
        render();
        return;
      }

      const attachmentTempAllowButton = target.closest<HTMLElement>("[data-temp-allow-attachment]");

      if (attachmentTempAllowButton?.dataset.tempAllowAttachment) {
        const finding = attachmentFindings.find((item) => item.id === attachmentTempAllowButton.dataset.tempAllowAttachment);

        if (!finding) {
          return;
        }

        tempAllowTarget = { kind: "attachment", id: finding.id };
        tempAllowMinutes = 60;
        render();
        return;
      }
    });

    window.addEventListener("keydown", onWindowKeydown, true);
  });
}

const modalStyles = `
  :host {
    all: initial;
    color-scheme: dark;
    --pp-bg-1: #343541;
    --pp-bg-2: #343541;
    --pp-panel: #40414f;
    --pp-panel-strong: #40414f;
    --pp-stroke: rgba(236, 236, 241, 0.12);
    --pp-text: #ececf1;
    --pp-muted: rgba(236, 236, 241, 0.64);
    --pp-ink-soft: rgba(236, 236, 241, 0.78);
    --pp-accent: #10a37f;
    --pp-accent-soft: rgba(16, 163, 127, 0.16);
    --pp-secret: #ef4444;
    --pp-secret-soft: rgba(239, 68, 68, 0.16);
    --pp-pii: #f59e0b;
    --pp-pii-soft: rgba(245, 158, 11, 0.16);
  }

  * {
    box-sizing: border-box;
    font-family: "Aptos", "Segoe UI Variable Display", "SF Pro Display", system-ui, sans-serif;
  }

  .pp-overlay {
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    display: grid;
    place-items: center;
    background:
      radial-gradient(circle at top left, rgba(16, 163, 127, 0.14), transparent 22%),
      rgba(0, 0, 0, 0.62);
    padding: 20px;
  }

  .pp-dialog {
    width: min(900px, 100%);
    max-height: min(90vh, 960px);
    overflow: auto;
    border-radius: 28px;
    background: linear-gradient(180deg, var(--pp-bg-1) 0%, var(--pp-bg-2) 100%);
    color: var(--pp-text);
    border: 1px solid var(--pp-stroke);
    box-shadow: 0 32px 100px rgba(10, 14, 21, 0.34);
    padding: 24px;
  }

  .pp-hero,
  .pp-actions,
  .pp-block__top,
  .pp-finding__top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .pp-hero {
    padding: 18px;
    border-radius: 24px;
    background:
      radial-gradient(circle at top left, rgba(95, 239, 223, 0.16), transparent 26%),
      linear-gradient(145deg, #10141e 0%, #1b2230 60%, #13241e 100%);
    color: white;
    margin-bottom: 16px;
  }

  .pp-eyebrow {
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-size: 12px;
    color: rgba(236, 236, 241, 0.8);
  }

  #pp-title {
    margin: 8px 0 10px;
    font-size: 30px;
    line-height: 1.1;
    max-width: 13ch;
  }

  .pp-copy {
    margin: 0;
    max-width: 58ch;
    color: rgba(236, 236, 241, 0.78);
    line-height: 1.5;
  }

  .pp-shield {
    flex-shrink: 0;
    padding: 14px 18px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.12);
    color: white;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    backdrop-filter: blur(16px);
  }

  .pp-metrics {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 18px;
  }

  .pp-metric {
    padding: 14px;
    border-radius: 18px;
    background: rgba(64, 65, 79, 0.9);
    border: 1px solid var(--pp-stroke);
    box-shadow: 0 14px 30px rgba(0, 0, 0, 0.28);
  }

  .pp-metric strong {
    display: block;
    margin-top: 8px;
    font-size: 20px;
    line-height: 1.1;
    word-break: break-word;
  }

  .pp-metric__label,
  .pp-inline-note,
  .pp-footer-note,
  .pp-finding__explanation {
    font-size: 12px;
    color: var(--pp-muted);
  }

  .pp-block {
    margin-top: 16px;
    padding: 14px;
    border-radius: 22px;
    border: 1px solid var(--pp-stroke);
    background: rgba(64, 65, 79, 0.72);
    box-shadow: 0 14px 30px rgba(0, 0, 0, 0.24);
  }

  .pp-section-title {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--pp-muted);
  }

  .pp-preview {
    margin-top: 12px;
    border-radius: 18px;
    border: 1px solid var(--pp-stroke);
    background: rgba(52, 53, 65, 0.72);
    color: var(--pp-text);
    padding: 16px;
    white-space: pre-wrap;
    line-height: 1.55;
    max-height: 220px;
    overflow: auto;
  }

  .pp-preview--replacement {
    background: var(--pp-accent-soft);
  }

  .pp-mark {
    padding: 1px 3px;
    border-radius: 6px;
    font-weight: 700;
  }

  .pp-mark--secret {
    background: var(--pp-secret-soft);
    color: var(--pp-text);
  }

  .pp-mark--pii {
    background: var(--pp-pii-soft);
    color: var(--pp-text);
  }

  .pp-mark--replacement {
    background: var(--pp-accent-soft);
    color: var(--pp-text);
  }

  .pp-finding-list {
    list-style: none;
    padding: 0;
    margin: 12px 0 0;
    display: grid;
    gap: 10px;
  }

  .pp-finding {
    border-radius: 16px;
    border: 1px solid var(--pp-stroke);
    background: rgba(64, 65, 79, 0.9);
    padding: 12px;
  }

  .pp-pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

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

  .pp-badge--secret {
    background: var(--pp-secret-soft);
    color: var(--pp-secret);
  }

  .pp-badge--pii {
    background: var(--pp-pii-soft);
    color: var(--pp-pii);
  }

  .pp-badge--neutral {
    background: rgba(236, 236, 241, 0.1);
    color: rgba(236, 236, 241, 0.78);
  }

  .pp-finding__snippet {
    display: block;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--pp-text);
    margin: 10px 0 8px;
  }

  .pp-finding__explanation {
    margin: 0;
    line-height: 1.5;
  }

  .pp-why-list {
    margin: 10px 0 0 16px;
    padding: 0;
    color: var(--pp-ink-soft);
    line-height: 1.5;
  }

  .pp-actions {
    justify-content: flex-end;
    flex-wrap: wrap;
    margin-top: 18px;
  }

  .pp-button,
  .pp-mini-button,
  .pp-mode-button {
    border: 0;
    cursor: pointer;
    color: var(--pp-text);
  }

  .pp-button {
    border-radius: 999px;
    padding: 12px 18px;
    font-size: 14px;
    font-weight: 700;
    background: rgba(236, 236, 241, 0.1);
    border: 1px solid var(--pp-stroke);
  }

  .pp-allow-row {
    display: flex;
    gap: 8px;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: wrap;
  }

  .pp-button--ghost {
    background: transparent;
    color: rgba(236, 236, 241, 0.86);
    border: 1px solid rgba(236, 236, 241, 0.16);
  }

  .pp-button--primary {
    background: linear-gradient(135deg, var(--pp-accent), #0b9487);
    color: white;
    border: 1px solid rgba(16, 163, 127, 0.32);
  }

  .pp-button--secondary {
    background: rgba(236, 236, 241, 0.08);
    border: 1px solid var(--pp-stroke);
  }

  .pp-mini-button {
    padding: 8px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    background: rgba(236, 236, 241, 0.1);
    border: 1px solid var(--pp-stroke);
  }

  .pp-mini-button--ghost {
    background: transparent;
    color: rgba(236, 236, 241, 0.82);
    border: 1px solid rgba(236, 236, 241, 0.16);
  }

  .pp-mode-row {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 6px;
    padding: 6px;
    border-radius: 999px;
    background: rgba(236, 236, 241, 0.06);
    border: 1px solid var(--pp-stroke);
  }

  .pp-mode-button {
    padding: 8px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 650;
    background: transparent;
    border: 1px solid transparent;
    color: rgba(236, 236, 241, 0.78);
  }

  .pp-mode-button:hover {
    background: rgba(236, 236, 241, 0.08);
    color: rgba(236, 236, 241, 0.92);
  }

  .pp-mode-button:focus-visible,
  .pp-button:focus-visible,
  .pp-mini-button:focus-visible {
    outline: 2px solid rgba(16, 163, 127, 0.62);
    outline-offset: 2px;
  }

  .pp-mode-button.is-active {
    background: var(--pp-accent-soft);
    color: rgba(236, 236, 241, 0.94);
    border-color: rgba(16, 163, 127, 0.42);
  }

  .pp-empty-note {
    color: var(--pp-muted);
  }

  @media (max-width: 760px) {
    .pp-dialog {
      padding: 18px;
      border-radius: 20px;
    }

    .pp-hero,
    .pp-actions,
    .pp-block__top,
    .pp-finding__top {
      display: grid;
      justify-content: stretch;
    }

    .pp-metrics {
      grid-template-columns: 1fr;
    }

    #pp-title {
      font-size: 24px;
    }

    .pp-button {
      width: 100%;
    }
  }
`;
