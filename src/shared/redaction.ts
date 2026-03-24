import type { DetectionFinding, RedactionMode } from "./types";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function fullRedactionPlaceholder(): string {
  return "[REDACTED]";
}

function partialMask(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();

  if (compact.length <= 6) {
    return `${compact.slice(0, 1)}***`;
  }

  return `${compact.slice(0, 4)}${"*".repeat(Math.max(4, compact.length - 6))}${compact.slice(-2)}`;
}

function replacementForFinding(finding: DetectionFinding, mode: RedactionMode): string {
  if (mode === "placeholder") {
    return finding.placeholder;
  }

  if (mode === "partial-mask") {
    return partialMask(finding.match);
  }

  return fullRedactionPlaceholder();
}

export function applyRedactionMode(text: string, findings: DetectionFinding[], mode: RedactionMode): { text: string } {
  let output = text;

  for (const finding of [...findings].sort((left, right) => right.start - left.start)) {
    output = `${output.slice(0, finding.start)}${replacementForFinding(finding, mode)}${output.slice(finding.end)}`;
  }

  return { text: output };
}

export function buildHighlightedHtml(text: string, findings: DetectionFinding[]): string {
  let cursor = 0;
  let output = "";

  for (const finding of [...findings].sort((left, right) => left.start - right.start)) {
    output += escapeHtml(text.slice(cursor, finding.start));
    output += `<mark class="pp-mark pp-mark--${finding.category}">${escapeHtml(text.slice(finding.start, finding.end))}</mark>`;
    cursor = finding.end;
  }

  output += escapeHtml(text.slice(cursor));
  return output;
}

export function buildReplacementPreviewHtml(text: string, findings: DetectionFinding[], mode: RedactionMode): string {
  let cursor = 0;
  let output = "";

  for (const finding of [...findings].sort((left, right) => left.start - right.start)) {
    output += escapeHtml(text.slice(cursor, finding.start));
    output += `<mark class="pp-mark pp-mark--replacement">${escapeHtml(replacementForFinding(finding, mode))}</mark>`;
    cursor = finding.end;
  }

  output += escapeHtml(text.slice(cursor));
  return output;
}

export function maskSnippet(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();

  if (compact.length <= 10) {
    return `${compact.slice(0, 2)}...`;
  }

  return `${compact.slice(0, 6)}...${compact.slice(-4)}`;
}

export function redactionModeLabel(mode: RedactionMode): string {
  switch (mode) {
    case "placeholder":
      return "Safe rewrite";
    case "partial-mask":
      return "Mask";
    case "full-redact":
      return "Full redact";
    default:
      return "Rewrite";
  }
}
