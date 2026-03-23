import type {
  CustomPattern,
  DetectionFinding,
  DetectionResult,
  FindingCategory,
  FindingSeverity,
  PromptProtectSettings
} from "./types";

interface RuleDefinition {
  id: string;
  label: string;
  category: FindingCategory;
  pattern: string;
  flags: string;
  source: "builtin" | "custom";
}

const BUILTIN_RULES: RuleDefinition[] = [
  {
    id: "openai-key",
    label: "OpenAI-style API key",
    category: "secret",
    pattern: "\\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\\b",
    flags: "g",
    source: "builtin"
  },
  {
    id: "aws-access-key",
    label: "AWS access key",
    category: "secret",
    pattern: "\\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\\b",
    flags: "g",
    source: "builtin"
  },
  {
    id: "github-token",
    label: "GitHub token",
    category: "secret",
    pattern: "\\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\\b",
    flags: "g",
    source: "builtin"
  },
  {
    id: "jwt",
    label: "JWT token",
    category: "secret",
    pattern: "\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b",
    flags: "g",
    source: "builtin"
  },
  {
    id: "pem-private-key",
    label: "Private key block",
    category: "secret",
    pattern:
      "-----BEGIN(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----[\\s\\S]+?-----END(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----",
    flags: "g",
    source: "builtin"
  },
  {
    id: "email",
    label: "Email address",
    category: "pii",
    pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
    flags: "gi",
    source: "builtin"
  },
  {
    id: "phone",
    label: "Phone number",
    category: "pii",
    pattern: "(?<!\\w)(?:\\+?\\d{1,3}[\\s().-]*)?(?:\\d[\\s().-]*){9,14}\\d(?!\\w)",
    flags: "g",
    source: "builtin"
  }
];

function severityForCategory(category: FindingCategory): FindingSeverity {
  return category === "secret" ? "high" : "medium";
}

function buildRuntimeRules(settings: PromptProtectSettings): RuleDefinition[] {
  const rules = BUILTIN_RULES.filter((rule) => {
    if (rule.category === "secret") {
      return settings.detectSecrets;
    }

    return settings.detectPII;
  });

  const customRules = settings.customPatterns
    .filter((pattern) => pattern.enabled)
    .map<RuleDefinition | null>((pattern) => customPatternToRule(pattern))
    .filter((pattern): pattern is RuleDefinition => pattern !== null);

  return [...rules, ...customRules];
}

function customPatternToRule(pattern: CustomPattern): RuleDefinition | null {
  try {
    new RegExp(pattern.pattern, ensureGlobalFlag(pattern.flags));
  } catch {
    return null;
  }

  return {
    id: pattern.id,
    label: pattern.label,
    category: pattern.category,
    pattern: pattern.pattern,
    flags: ensureGlobalFlag(pattern.flags),
    source: "custom"
  };
}

function ensureGlobalFlag(flags: string): string {
  const sanitized = Array.from(new Set(flags.replace(/[^dgimsuy]/g, "").split(""))).join("");
  return sanitized.includes("g") ? sanitized : `${sanitized}g`;
}

function collectMatches(text: string, rule: RuleDefinition): DetectionFinding[] {
  const matches: DetectionFinding[] = [];
  const regex = new RegExp(rule.pattern, ensureGlobalFlag(rule.flags));
  let result: RegExpExecArray | null;

  while ((result = regex.exec(text)) !== null) {
    const match = result[0];
    const start = result.index;
    const end = start + match.length;

    if (!match) {
      regex.lastIndex += 1;
      continue;
    }

    if (rule.id === "phone" && !looksLikePhoneNumber(match)) {
      continue;
    }

    matches.push({
      id: crypto.randomUUID(),
      ruleId: rule.id,
      label: rule.label,
      category: rule.category,
      severity: severityForCategory(rule.category),
      source: rule.source,
      start,
      end,
      match
    });
  }

  return matches;
}

function looksLikePhoneNumber(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  return digits.length >= 10 && digits.length <= 15;
}

function scoreFinding(finding: DetectionFinding): number {
  const severity = finding.severity === "high" ? 1000 : 100;
  const span = finding.end - finding.start;
  return severity + span;
}

function dedupeOverlaps(findings: DetectionFinding[]): DetectionFinding[] {
  const ordered = [...findings].sort((left, right) => {
    if (left.start !== right.start) {
      return left.start - right.start;
    }

    return scoreFinding(right) - scoreFinding(left);
  });

  const deduped: DetectionFinding[] = [];

  for (const finding of ordered) {
    const current = deduped.at(-1);

    if (!current || finding.start >= current.end) {
      deduped.push(finding);
      continue;
    }

    if (scoreFinding(finding) > scoreFinding(current)) {
      deduped[deduped.length - 1] = finding;
    }
  }

  return deduped;
}

export function detectSensitiveContent(text: string, settings: PromptProtectSettings): DetectionResult {
  const findings = buildRuntimeRules(settings).flatMap((rule) => collectMatches(text, rule));
  const deduped = dedupeOverlaps(findings);
  const ruleLabels = Array.from(new Set(deduped.map((finding) => finding.label)));

  return {
    findings: deduped,
    summary: {
      total: deduped.length,
      secrets: deduped.filter((finding) => finding.category === "secret").length,
      pii: deduped.filter((finding) => finding.category === "pii").length,
      ruleLabels
    }
  };
}

