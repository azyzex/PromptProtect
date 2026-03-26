import { DEFAULT_SETTINGS, MAX_ALLOW_RULES, STORAGE_KEYS, TEXT_ATTACHMENT_EXTENSIONS } from "../shared/defaults";
import { detectSensitiveContent } from "../shared/detector";
import { applyRedactionMode, maskSnippet } from "../shared/redaction";
import { runtimeApi } from "../shared/runtime";
import { getSupportedSiteForHostname } from "../shared/sites";
import type {
  AppendLogPayload,
  AttachmentFinding,
  DetectionResult,
  InlineScanSnapshot,
  PageDiagnostics,
  PageMessageRequest,
  PromptProtectSettings,
  RedactionMode,
  SiteProfile
} from "../shared/types";
import { createInlineChipController } from "./chip";
import {
  type ComposerElement,
  findAnySendButton,
  findNearestSendButton,
  findPreferredComposer,
  focusComposer,
  readComposerText,
  resolveComposer,
  resolveSendButton,
  writeComposerText
} from "./dom";
import { openReviewModal, type ReviewDecision } from "./modal";

type SubmissionTrigger = "keyboard" | "click";

interface PendingAttachmentScan {
  key: string;
  fileName: string;
  fileType: string;
  findings: AttachmentFinding[];
}

const MODAL_ROOT_ID = "promptprotect-modal-root";
const CHIP_ROOT_ID = "promptprotect-inline-chip";
const IGNORED_SELECTOR = `#${MODAL_ROOT_ID}, #${CHIP_ROOT_ID}`;

let settingsCache: PromptProtectSettings | null = null;
let modalOpen = false;
let allowNextSubmission = false;
let lastInlineScan: InlineScanSnapshot | null = null;
let pageReady = false;

let cachedComposer: ComposerElement | null = null;
let cachedSendButton: HTMLElement | null = null;
let uiObserver: MutationObserver | null = null;
let uiRefreshTimer: number | null = null;

const pendingAttachmentScans = new Map<string, PendingAttachmentScan>();
const fileInputToKeys = new WeakMap<HTMLInputElement, string[]>();
const inlineChip = createInlineChipController(CHIP_ROOT_ID);

void bootstrap();

async function bootstrap() {
  if (!getSupportedSiteForHostname(window.location.hostname)) {
    return;
  }

  settingsCache = await runtimeApi.getSettings().catch(() => DEFAULT_SETTINGS);
  pageReady = true;

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes[STORAGE_KEYS.settings]?.newValue) {
      settingsCache = changes[STORAGE_KEYS.settings].newValue as PromptProtectSettings;
    }
  });

  chrome.runtime.onMessage.addListener((message: PageMessageRequest, _sender, sendResponse) => {
    if (message.type === "promptprotect:get-page-diagnostics") {
      sendResponse(buildPageDiagnostics());
    }
  });

  document.addEventListener("keydown", handleKeydown, true);
  document.addEventListener("click", handleClick, true);
  document.addEventListener("submit", handleSubmit, true);
  document.addEventListener("paste", handlePaste, true);
  document.addEventListener("change", handleFileInputChange, true);

  installUiObserver();
}

function clearUiRefreshTimer() {
  if (uiRefreshTimer !== null) {
    window.clearTimeout(uiRefreshTimer);
    uiRefreshTimer = null;
  }
}

function scheduleUiRefresh() {
  clearUiRefreshTimer();

  uiRefreshTimer = window.setTimeout(() => {
    uiRefreshTimer = null;
    refreshUiCache();
  }, 75);
}

function refreshUiCache() {
  const hostname = window.location.hostname;

  const composer = findPreferredComposer(hostname, IGNORED_SELECTOR);
  cachedComposer = composer && composer instanceof Element && document.contains(composer) ? composer : null;

  if (composer && composer instanceof HTMLElement) {
    const button = findNearestSendButton(composer, hostname, IGNORED_SELECTOR);
    cachedSendButton = button && document.contains(button) ? button : null;
    return;
  }

  const anyButton = findAnySendButton(hostname);
  cachedSendButton = anyButton && document.contains(anyButton) ? anyButton : null;
}

function installUiObserver() {
  refreshUiCache();

  if (uiObserver) {
    return;
  }

  uiObserver = new MutationObserver(() => scheduleUiRefresh());
  const root = document.body ?? document.documentElement;

  try {
    uiObserver.observe(root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["disabled", "aria-disabled"]
    });
  } catch {
    // Ignore observer failures.
  }

  window.addEventListener("focusin", scheduleUiRefresh, true);
  window.addEventListener("visibilitychange", scheduleUiRefresh, true);
}

async function getSettings(): Promise<PromptProtectSettings> {
  if (settingsCache) {
    return settingsCache;
  }

  settingsCache = await runtimeApi.getSettings().catch(() => DEFAULT_SETTINGS);
  return settingsCache;
}

function getCurrentProfile(settings: PromptProtectSettings): SiteProfile | null {
  return settings.siteProfiles[window.location.hostname] ?? null;
}

function isGuardEnabled(settings: PromptProtectSettings): settings is PromptProtectSettings {
  const profile = getCurrentProfile(settings);
  return Boolean(settings.enabled && profile?.enabled);
}

function getPreferredRedactionMode(settings: PromptProtectSettings): RedactionMode {
  return getCurrentProfile(settings)?.redactionMode ?? settings.defaultRedactionMode;
}

function updateLastInlineScan(type: InlineScanSnapshot["type"], total: number) {
  lastInlineScan = {
    type,
    total,
    at: new Date().toISOString()
  };
}

function aggregateAttachmentFindings(): AttachmentFinding[] {
  return Array.from(pendingAttachmentScans.values()).flatMap((entry) => entry.findings);
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

  const composer =
    resolveComposer(event.target, window.location.hostname, IGNORED_SELECTOR) ??
    (cachedComposer && cachedComposer instanceof Element && document.contains(cachedComposer) ? cachedComposer : null);

  if (!composer) {
    return;
  }

  const resolvedSendButton = findNearestSendButton(composer, window.location.hostname, IGNORED_SELECTOR);
  const sendButton = resolvedSendButton ?? (cachedSendButton && document.contains(cachedSendButton) ? cachedSendButton : null);

  await inspectSubmission({
    trigger: "keyboard",
    composer,
    sendButton,
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

  const sendButton =
    resolveSendButton(event.target, window.location.hostname, IGNORED_SELECTOR) ??
    (cachedSendButton && document.contains(cachedSendButton) ? cachedSendButton : null);

  if (!sendButton) {
    return;
  }

  const composer =
    resolveComposer(document.activeElement, window.location.hostname, IGNORED_SELECTOR) ??
    (cachedComposer && cachedComposer instanceof Element && document.contains(cachedComposer) ? cachedComposer : null) ??
    findPreferredComposer(window.location.hostname, IGNORED_SELECTOR);

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

async function handleSubmit(event: Event) {
  if (allowNextSubmission) {
    allowNextSubmission = false;
    return;
  }

  if (modalOpen || event.defaultPrevented) {
    return;
  }

  const composer =
    resolveComposer(document.activeElement, window.location.hostname, IGNORED_SELECTOR) ??
    (cachedComposer && cachedComposer instanceof Element && document.contains(cachedComposer) ? cachedComposer : null) ??
    findPreferredComposer(window.location.hostname, IGNORED_SELECTOR);

  if (!composer) {
    return;
  }

  const submitEvent = event as SubmitEvent;
  const submitter = submitEvent.submitter ?? null;
  const resolvedSendButton = submitter ? resolveSendButton(submitter, window.location.hostname, IGNORED_SELECTOR) : null;
  const sendButton =
    resolvedSendButton ??
    (composer instanceof HTMLElement ? findNearestSendButton(composer, window.location.hostname, IGNORED_SELECTOR) : null) ??
    (cachedSendButton && document.contains(cachedSendButton) ? cachedSendButton : null);

  await inspectSubmission({
    trigger: "keyboard",
    composer,
    sendButton,
    event
  });
}

async function handlePaste(event: ClipboardEvent) {
  const settings = await getSettings();

  if (!isGuardEnabled(settings) || modalOpen) {
    return;
  }

  const profile = getCurrentProfile(settings);

  if (!settings.scanOnPaste || !profile?.scanOnPaste) {
    return;
  }

  const pastedText = event.clipboardData?.getData("text/plain") ?? "";

  if (pastedText.trim()) {
    const result = detectSensitiveContent(pastedText, settings, {
      hostname: window.location.hostname,
      origin: "composer"
    });

    if (result.findings.length) {
      updateLastInlineScan("paste", result.summary.total);
      await logFinding("pasted_flagged", result, {
        trigger: "paste",
        mode: "none",
        note: "PromptProtect flagged pasted text before send."
      });

      const composer =
        resolveComposer(event.target, window.location.hostname, IGNORED_SELECTOR) ??
        findPreferredComposer(window.location.hostname, IGNORED_SELECTOR);

      if (composer && settings.showInlineWarnings) {
        inlineChip.show(composer, `${result.summary.total} pasted item${result.summary.total === 1 ? "" : "s"} look sensitive. Review before send.`);
      }
    }
  }

  if (settings.scanAttachments && profile?.scanAttachments) {
    const files = Array.from(event.clipboardData?.files ?? []);

    if (files.length) {
      const aggregate = await scanAttachmentFiles(files, `paste:${crypto.randomUUID()}`);

      if (aggregate > 0) {
        const composer = findPreferredComposer(window.location.hostname, IGNORED_SELECTOR);

        if (composer && settings.showInlineWarnings) {
          inlineChip.show(composer, `${aggregate} attachment finding${aggregate === 1 ? "" : "s"} detected. PromptProtect will review attachments before send.`);
        }
      }
    }
  }
}

async function handleFileInputChange(event: Event) {
  const settings = await getSettings();

  if (!isGuardEnabled(settings)) {
    return;
  }

  const profile = getCurrentProfile(settings);

  if (!settings.scanAttachments || !profile?.scanAttachments) {
    return;
  }

  const target = event.target;

  if (!(target instanceof HTMLInputElement) || target.type !== "file") {
    return;
  }

  const previousKeys = fileInputToKeys.get(target) ?? [];

  for (const key of previousKeys) {
    pendingAttachmentScans.delete(key);
  }

  if (!target.files?.length) {
    fileInputToKeys.set(target, []);
    return;
  }

  const scope = `input:${crypto.randomUUID()}`;
  const aggregate = await scanAttachmentFiles(Array.from(target.files), scope);
  const nextKeys = Array.from(pendingAttachmentScans.values())
    .filter((entry) => entry.key.startsWith(scope))
    .map((entry) => entry.key);

  fileInputToKeys.set(target, nextKeys);

  if (aggregate > 0 && settings.showInlineWarnings) {
    const composer = findPreferredComposer(window.location.hostname, IGNORED_SELECTOR);

    if (composer) {
      inlineChip.show(composer, `${aggregate} attachment finding${aggregate === 1 ? "" : "s"} detected. PromptProtect will block send for review.`);
    }
  }
}

async function scanAttachmentFiles(files: File[], scope: string): Promise<number> {
  const settings = await getSettings();

  if (!isGuardEnabled(settings)) {
    return 0;
  }

  let totalFindings = 0;

  for (const file of files) {
    const scan = await scanAttachmentFile(file, settings, scope);

    if (!scan) {
      continue;
    }

    pendingAttachmentScans.set(scan.key, scan);
    totalFindings += scan.findings.length;
  }

  if (totalFindings > 0) {
    updateLastInlineScan("attachment", totalFindings);
    await runtimeApi
      .appendLog({
      hostname: window.location.hostname,
      siteLabel: getSupportedSiteForHostname(window.location.hostname)?.label ?? window.location.hostname,
      action: "attachment_flagged",
      totalFindings,
      secrets: aggregateAttachmentFindings().filter((finding) => finding.category === "secret").length,
      pii: aggregateAttachmentFindings().filter((finding) => finding.category === "pii").length,
      ruleLabels: Array.from(new Set(aggregateAttachmentFindings().map((finding) => finding.label))),
      trigger: "attachment",
      mode: "none",
      note: "PromptProtect found potential issues in an attached file."
    })
      .catch(() => null);
  }

  return totalFindings;
}

async function scanAttachmentFile(
  file: File,
  settings: PromptProtectSettings,
  scope: string
): Promise<PendingAttachmentScan | null> {
  if (!isTextLikeAttachment(file)) {
    return null;
  }

  const text = await file.text();

  if (!text.trim()) {
    return null;
  }

  const result = detectSensitiveContent(text.slice(0, 250_000), settings, {
    hostname: window.location.hostname,
    origin: "attachment"
  });

  if (!result.findings.length) {
    return null;
  }

  return {
    key: `${scope}:${file.name}:${file.size}:${file.lastModified}`,
    fileName: file.name,
    fileType: file.type || "text/plain",
    findings: result.findings.map((finding) => ({
      id: crypto.randomUUID(),
      fileName: file.name,
      fileType: file.type || "text/plain",
      ruleId: finding.ruleId,
      label: finding.label,
      category: finding.category,
      severity: finding.severity,
      source: finding.source,
      matchPreview: maskSnippet(finding.match),
      placeholder: finding.placeholder,
      explanation: finding.explanation,
      confidence: finding.confidence,
      confidenceLabel: finding.confidenceLabel,
      why: finding.why,
      allowFingerprint: finding.allowFingerprint
    }))
  };
}

function isTextLikeAttachment(file: File): boolean {
  if (file.type.startsWith("text/")) {
    return true;
  }

  const lower = file.name.toLowerCase();
  return TEXT_ATTACHMENT_EXTENSIONS.some((extension) => lower.endsWith(extension));
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
  const emptyResult: DetectionResult = {
    findings: [],
    summary: { total: 0, secrets: 0, pii: 0, critical: 0, highConfidence: 0, ruleLabels: [], topCategory: null }
  };
  const textResult = rawText.trim()
    ? detectSensitiveContent(rawText, settings, {
        hostname: window.location.hostname,
        origin: "composer"
      })
    : emptyResult;
  const attachmentFindings = aggregateAttachmentFindings();

  if (!textResult.findings.length && !attachmentFindings.length) {
    return;
  }

  context.event.preventDefault();
  context.event.stopPropagation();
  context.event.stopImmediatePropagation();
  updateLastInlineScan("send", textResult.summary.total + attachmentFindings.length);
  modalOpen = true;
  inlineChip.hide();

  try {
    const decision = await openReviewModal({
      hostId: MODAL_ROOT_ID,
      siteLabel: getSupportedSiteForHostname(window.location.hostname)?.label ?? window.location.hostname,
      originalText: rawText,
      composerFindings: textResult.findings,
      attachmentFindings,
      defaultMode: getPreferredRedactionMode(settings),
      onAllowComposer: async (finding) => {
        await addAllowRule(finding.ruleId, finding.allowFingerprint, `${finding.label} allowlisted on site`);
      },
      onAllowAttachment: async (finding) => {
        await addAllowRule(finding.ruleId, finding.allowFingerprint, `${finding.label} allowlisted on site`);
        removeAttachmentFindingFromState(finding);
      },
      onAllowComposerTemporarily: async (finding, minutes) => {
        await allowTemporarily(finding.ruleId, finding.allowFingerprint, `${finding.label} allowlisted on site`, minutes);
      },
      onAllowAttachmentTemporarily: async (finding, minutes) => {
        await allowTemporarily(finding.ruleId, finding.allowFingerprint, `${finding.label} allowlisted on site`, minutes);
        removeAttachmentFindingFromState(finding);
      }
    });

    await handleReviewDecision(decision, context, rawText, textResult);
  } finally {
    modalOpen = false;
  }
}

async function handleReviewDecision(
  decision: ReviewDecision,
  context: { trigger: SubmissionTrigger; composer: ComposerElement; sendButton: HTMLElement | null },
  rawText: string,
  textResult: DetectionResult
) {
  if (decision.type === "cancel") {
    await logFinding("cancelled", textResult, {
      trigger: "send",
      mode: "none",
      note: "The user canceled after reviewing the findings."
    });
    focusComposer(context.composer);
    return;
  }

  if (decision.type === "allowlisted-send") {
    await logFinding("allowlisted", textResult, {
      trigger: "send",
      mode: "none",
      note: "Current findings were allowlisted for this site before send."
    });
    await submitWithoutChanges(context.composer, context.sendButton, context.trigger);
    return;
  }

  if (decision.type === "ignore-once") {
    await logFinding("ignored_once", textResult, {
      trigger: "send",
      mode: "none",
      note: "The user chose to ignore the warning once and send original content."
    });
    await submitWithoutChanges(context.composer, context.sendButton, context.trigger);
    return;
  }

  const rewritten = applyRedactionMode(rawText, textResult.findings, decision.mode);
  writeComposerText(context.composer, rewritten.text);
  await logFinding(actionForMode(decision.mode), textResult, {
    trigger: "send",
    mode: decision.mode,
    note:
      aggregateAttachmentFindings().length > 0
        ? "Composer text was rewritten before send. Attachments remained unchanged after review."
        : "Composer text was rewritten before send."
  });
  await wait(80);
  await submitWithoutChanges(context.composer, context.sendButton, context.trigger);
}

function actionForMode(mode: RedactionMode): AppendLogPayload["action"] {
  if (mode === "placeholder") {
    return "safe_rewrite";
  }

  if (mode === "partial-mask") {
    return "masked";
  }

  return "redacted";
}

async function logFinding(
  action: AppendLogPayload["action"],
  result: DetectionResult,
  options: Pick<AppendLogPayload, "trigger" | "mode" | "note">
) {
  const site = getSupportedSiteForHostname(window.location.hostname);
  const attachmentFindings = aggregateAttachmentFindings();

  await runtimeApi
    .appendLog({
    hostname: window.location.hostname,
    siteLabel: site?.label ?? window.location.hostname,
    action,
    totalFindings: result.summary.total + attachmentFindings.length,
    secrets:
      result.summary.secrets + attachmentFindings.filter((finding) => finding.category === "secret").length,
    pii: result.summary.pii + attachmentFindings.filter((finding) => finding.category === "pii").length,
    ruleLabels: Array.from(new Set([...result.summary.ruleLabels, ...attachmentFindings.map((finding) => finding.label)])),
    trigger: options.trigger,
    mode: options.mode,
    note: options.note
  })
    .catch(() => null);
}

async function addAllowRule(ruleId: string, allowFingerprint: string, label: string, expiresAt?: string) {
  const settings = await getSettings();

  if (!settings) {
    return;
  }

  const hostname = window.location.hostname;
  const now = Date.now();
  const existingIndex = settings.exactAllowRules.findIndex(
    (rule) =>
      rule.hostname === hostname &&
      rule.ruleId === ruleId &&
      rule.matchFingerprint === allowFingerprint &&
      (!rule.expiresAt || Date.parse(rule.expiresAt) > now)
  );

  const nextEntry = {
    id: existingIndex >= 0 ? settings.exactAllowRules[existingIndex].id : crypto.randomUUID(),
    hostname,
    ruleId,
    matchFingerprint: allowFingerprint,
    label,
    createdAt: existingIndex >= 0 ? settings.exactAllowRules[existingIndex].createdAt : new Date().toISOString(),
    expiresAt
  };

  const remaining = settings.exactAllowRules.filter((rule, index) => index !== existingIndex);

  settingsCache = await runtimeApi
    .saveSettings({
      ...settings,
      exactAllowRules: [nextEntry, ...remaining].slice(0, MAX_ALLOW_RULES)
    })
    .catch(() => settings);
}

async function allowTemporarily(ruleId: string, allowFingerprint: string, label: string, minutes: number) {
  const boundedMinutes = Math.max(1, Math.min(60 * 24 * 30, Math.floor(minutes)));
  const expiresAt = new Date(Date.now() + boundedMinutes * 60_000).toISOString();
  await addAllowRule(ruleId, allowFingerprint, `${label} (temporary ${boundedMinutes}m)`, expiresAt);
}

function removeAttachmentFindingFromState(finding: AttachmentFinding) {
  for (const [key, scan] of pendingAttachmentScans.entries()) {
    if (!scan.findings.some((item) => item.id === finding.id)) {
      continue;
    }

    const nextFindings = scan.findings.filter((item) => item.id !== finding.id);

    if (!nextFindings.length) {
      pendingAttachmentScans.delete(key);
    } else {
      pendingAttachmentScans.set(key, {
        ...scan,
        findings: nextFindings
      });
    }
  }
}

function buildPageDiagnostics(): PageDiagnostics {
  const composer = findPreferredComposer(window.location.hostname, IGNORED_SELECTOR);
  const profile = settingsCache?.siteProfiles[window.location.hostname] ?? null;

  return {
    ready: pageReady,
    hostname: window.location.hostname,
    siteLabel: getSupportedSiteForHostname(window.location.hostname)?.label ?? null,
    composerFound: Boolean(composer),
    sendButtonFound: Boolean(composer ? findNearestSendButton(composer, window.location.hostname, IGNORED_SELECTOR) : findAnySendButton(window.location.hostname)),
    pendingAttachmentFlags: aggregateAttachmentFindings().length,
    lastInlineScan,
    profile
  };
}

async function submitWithoutChanges(composer: ComposerElement, sendButton: HTMLElement | null, trigger: SubmissionTrigger) {
  focusComposer(composer);
  await wait(32);
  allowNextSubmission = true;

  const fallbackComposer = composer instanceof HTMLElement ? composer : null;
  const button =
    sendButton && document.contains(sendButton)
      ? sendButton
      : fallbackComposer
        ? findNearestSendButton(fallbackComposer, window.location.hostname, IGNORED_SELECTOR)
        : null;

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
