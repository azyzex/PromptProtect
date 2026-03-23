import type { DetectionFinding } from "./types";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function placeholderForFinding(finding: DetectionFinding): string {
  const label = finding.label.toUpperCase().replace(/[^A-Z0-9 ]/g, "");
  return `[REDACTED ${label}]`;
}

export function redactText(text: string, findings: DetectionFinding[]): { text: string } {
  let output = text;

  for (const finding of [...findings].sort((left, right) => right.start - left.start)) {
    output = `${output.slice(0, finding.start)}${placeholderForFinding(finding)}${output.slice(finding.end)}`;
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

export function maskSnippet(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();

  if (compact.length <= 10) {
    return `${compact.slice(0, 2)}...`;
  }

  return `${compact.slice(0, 6)}...${compact.slice(-4)}`;
}

