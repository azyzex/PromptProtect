import type { LogEntry } from "../shared/types";

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

export function countLogsLastDays(logs: LogEntry[], days: number): number {
  const threshold = Date.now() - days * 24 * 60 * 60 * 1000;
  return logs.filter((entry) => new Date(entry.timestamp).getTime() >= threshold).length;
}

export function topRuleLabel(logs: LogEntry[]): string {
  const counts = new Map<string, number>();

  for (const entry of logs) {
    for (const label of entry.ruleLabels) {
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
  }

  let winner = "None yet";
  let max = 0;

  for (const [label, count] of counts.entries()) {
    if (count > max) {
      winner = label;
      max = count;
    }
  }

  return winner;
}

export function topCategory(logs: LogEntry[]): string {
  const secretTotal = logs.reduce((sum, entry) => sum + entry.secrets, 0);
  const piiTotal = logs.reduce((sum, entry) => sum + entry.pii, 0);

  if (!secretTotal && !piiTotal) {
    return "None yet";
  }

  return secretTotal >= piiTotal ? "Secrets" : "PII";
}
