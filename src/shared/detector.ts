import type {
  ConfidenceLabel,
  CustomPattern,
  DetectionFinding,
  DetectionOptions,
  DetectionResult,
  FindingCategory,
  FindingSeverity,
  PromptProtectSettings,
  StrictnessLevel
} from "./types";

interface RuleDefinition {
  id: string;
  label: string;
  category: FindingCategory;
  pattern: string;
  flags: string;
  source: "builtin" | "custom";
  explanation: string;
  placeholder: string;
  baseConfidence: number;
  captureGroup?: number;
  contextKeywords?: string[];
}

const STRICTNESS_THRESHOLDS: Record<StrictnessLevel, number> = {
  relaxed: 75,
  balanced: 58,
  strict: 38
};

const BUILTIN_RULES: RuleDefinition[] = [
  {
    id: "openai-key",
    label: "OpenAI-style API key",
    category: "secret",
    pattern: "\\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\\b",
    flags: "g",
    source: "builtin",
    explanation: "This matches the prefix and length pattern used by OpenAI-style API keys.",
    placeholder: "<OPENAI_API_KEY>",
    baseConfidence: 84,
    contextKeywords: ["openai", "api_key", "authorization", "bearer", "secret", "token"]
  },
  {
    id: "aws-access-key",
    label: "AWS access key",
    category: "secret",
    pattern: "\\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\\b",
    flags: "g",
    source: "builtin",
    explanation: "This looks like an AWS access key identifier.",
    placeholder: "<AWS_ACCESS_KEY_ID>",
    baseConfidence: 86,
    contextKeywords: ["aws", "access_key", "credentials", "iam", "secret", "token"]
  },
  {
    id: "github-token",
    label: "GitHub token",
    category: "secret",
    pattern: "\\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\\b",
    flags: "g",
    source: "builtin",
    explanation: "This matches the known prefixes used by GitHub personal, OAuth, or installation tokens.",
    placeholder: "<GITHUB_TOKEN>",
    baseConfidence: 88,
    contextKeywords: ["github", "token", "pat", "auth", "header"]
  },
  {
    id: "slack-token",
    label: "Slack token",
    category: "secret",
    pattern: "\\bxox(?:a|b|o|p|r|s)-[A-Za-z0-9-]{10,}\\b",
    flags: "g",
    source: "builtin",
    explanation: "Slack tokens typically start with xox followed by a token class prefix.",
    placeholder: "<SLACK_TOKEN>",
    baseConfidence: 88,
    contextKeywords: ["slack", "bot", "workspace", "token"]
  },
  {
    id: "stripe-secret-key",
    label: "Stripe secret key",
    category: "secret",
    pattern: "\\bsk_(?:live|test)_[0-9A-Za-z]{16,}\\b",
    flags: "g",
    source: "builtin",
    explanation: "Stripe secret keys use a stable sk_live or sk_test prefix.",
    placeholder: "<STRIPE_SECRET_KEY>",
    baseConfidence: 88,
    contextKeywords: ["stripe", "secret", "payment", "api"]
  },
  {
    id: "google-api-key",
    label: "Google API key",
    category: "secret",
    pattern: "\\bAIza[0-9A-Za-z\\-_]{35}\\b",
    flags: "g",
    source: "builtin",
    explanation: "Google API keys typically begin with AIza followed by a fixed-length token body.",
    placeholder: "<GOOGLE_API_KEY>",
    baseConfidence: 86,
    contextKeywords: ["google", "gcp", "maps", "api"]
  },
  {
    id: "jwt",
    label: "JWT token",
    category: "secret",
    pattern: "\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b",
    flags: "g",
    source: "builtin",
    explanation: "The three-part dot-separated structure matches a JSON Web Token.",
    placeholder: "<JWT_TOKEN>",
    baseConfidence: 82,
    contextKeywords: ["jwt", "bearer", "authorization", "token", "session"]
  },
  {
    id: "pem-private-key",
    label: "Private key block",
    category: "secret",
    pattern:
      "-----BEGIN(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----[\\s\\S]+?-----END(?: RSA| EC| DSA| OPENSSH)? PRIVATE KEY-----",
    flags: "g",
    source: "builtin",
    explanation: "This is a full private key block and should never be shared in a prompt.",
    placeholder: "<PRIVATE_KEY_BLOCK>",
    baseConfidence: 99,
    contextKeywords: ["private key", "ssh", "pem", "rsa"]
  },
  {
    id: "bearer-token",
    label: "Bearer token",
    category: "secret",
    pattern: "\\bBearer\\s+([A-Za-z0-9._~+/=-]{16,})\\b",
    flags: "gi",
    source: "builtin",
    explanation: "A bearer authorization header usually contains a live credential value after the scheme.",
    placeholder: "<BEARER_TOKEN>",
    baseConfidence: 86,
    captureGroup: 1,
    contextKeywords: ["bearer", "authorization", "header", "auth"]
  },
  {
    id: "auth-header",
    label: "Authorization header credential",
    category: "secret",
    pattern: "\\bAuthorization\\s*:\\s*(?:Bearer|Basic)\\s+([A-Za-z0-9._~+/=-]{16,})\\b",
    flags: "gi",
    source: "builtin",
    explanation: "This captures the credential portion of an HTTP Authorization header.",
    placeholder: "<AUTH_CREDENTIAL>",
    baseConfidence: 89,
    captureGroup: 1,
    contextKeywords: ["authorization", "header", "basic", "bearer", "auth"]
  },
  {
    id: "env-assignment",
    label: "Secret environment variable value",
    category: "secret",
    pattern:
      "(?:^|[\\r\\n])\\s*(?:OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN|STRIPE_SECRET_KEY|API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET)\\s*=\\s*[\"']?([^\"'\\r\\n\\s]+)[\"']?",
    flags: "gim",
    source: "builtin",
    explanation: "This looks like a real secret value assigned inside an .env-style configuration line.",
    placeholder: "<ENV_SECRET>",
    baseConfidence: 92,
    captureGroup: 1,
    contextKeywords: ["api_key", "secret_key", "token", "client_secret", "env"]
  },
  {
    id: "connection-string-password",
    label: "Connection string password",
    category: "secret",
    pattern: "\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp):\\/\\/[^\\s:@/]+:([^@\\s]+)@",
    flags: "gi",
    source: "builtin",
    explanation: "A database or queue connection string contains an embedded password value.",
    placeholder: "<CONNECTION_PASSWORD>",
    baseConfidence: 91,
    captureGroup: 1,
    contextKeywords: ["database", "connection string", "password", "postgres", "mongodb", "mysql"]
  },
  {
    id: "kv-secret-value",
    label: "Structured secret value",
    category: "secret",
    pattern: "(?:^|[;\\s])(?:password|pwd|client_secret|secret|token)\\s*=\\s*([^;\\s]+)",
    flags: "gim",
    source: "builtin",
    explanation: "This looks like a credential value in a key-value configuration string.",
    placeholder: "<SECRET_VALUE>",
    baseConfidence: 70,
    captureGroup: 1,
    contextKeywords: ["password", "secret", "token", "client_secret", "config"]
  },
  {
    id: "email",
    label: "Email address",
    category: "pii",
    pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
    flags: "gi",
    source: "builtin",
    explanation: "This appears to be a real email address and may identify a person or account.",
    placeholder: "<EMAIL_ADDRESS>",
    baseConfidence: 76,
    contextKeywords: ["email", "mail", "contact", "user"]
  },
  {
    id: "phone",
    label: "Phone number",
    category: "pii",
    pattern: "(?<!\\w)(?:\\+?\\d{1,3}[\\s().-]*)?(?:\\d[\\s().-]*){9,14}\\d(?!\\w)",
    flags: "g",
    source: "builtin",
    explanation: "This number looks like a phone number and may expose personal contact details.",
    placeholder: "<PHONE_NUMBER>",
    baseConfidence: 68,
    contextKeywords: ["phone", "mobile", "sms", "contact", "call"]
  }
];

export function sanitizePatternFlags(flags: string): string {
  return Array.from(new Set(flags.replace(/[^dgimsuy]/g, "").split("").filter(Boolean))).join("");
}

function ensureRuntimeFlags(flags: string): string {
  const sanitized = sanitizePatternFlags(flags);
  const required = new Set([...sanitized.split(""), "g", "d"]);
  return Array.from(required).join("");
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
    new RegExp(pattern.pattern, ensureRuntimeFlags(pattern.flags));
  } catch {
    return null;
  }

  return {
    id: pattern.id,
    label: pattern.label,
    category: pattern.category,
    pattern: pattern.pattern,
    flags: ensureRuntimeFlags(pattern.flags),
    source: "custom",
    explanation: pattern.explanation || `This matches the custom pattern "${pattern.label}".`,
    placeholder: pattern.placeholder || createPlaceholder(pattern.label),
    baseConfidence: pattern.category === "secret" ? 82 : 72,
    contextKeywords: []
  };
}

function createPlaceholder(label: string): string {
  const normalized = label.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return `<${normalized || "REDACTED"}>`;
}

function getStrictnessThreshold(settings: PromptProtectSettings, options?: DetectionOptions): number {
  if (options?.strictness) {
    return STRICTNESS_THRESHOLDS[options.strictness];
  }

  if (options?.hostname && settings.siteProfiles[options.hostname]) {
    return STRICTNESS_THRESHOLDS[settings.siteProfiles[options.hostname].strictness];
  }

  return STRICTNESS_THRESHOLDS.balanced;
}

function getContextWindow(text: string, start: number, end: number): string {
  const lineStart = Math.max(0, text.lastIndexOf("\n", Math.max(0, start - 1)) + 1);
  const nextLineBreak = text.indexOf("\n", end);
  const lineEnd = nextLineBreak === -1 ? text.length : nextLineBreak;
  return text.slice(lineStart, lineEnd).trim();
}

function extractMatchSpan(result: RegExpExecArray, captureGroup?: number): { start: number; end: number; match: string } {
  if (captureGroup === undefined || !result[captureGroup]) {
    return {
      start: result.index,
      end: result.index + result[0].length,
      match: result[0]
    };
  }

  const groupedMatch = result[captureGroup];
  const withIndices = result as RegExpExecArray & { indices?: Array<[number, number] | undefined> };
  const captureIndices = withIndices.indices?.[captureGroup];

  if (captureIndices) {
    return {
      start: captureIndices[0],
      end: captureIndices[1],
      match: groupedMatch
    };
  }

  const relativeIndex = result[0].indexOf(groupedMatch);
  return {
    start: result.index + Math.max(relativeIndex, 0),
    end: result.index + Math.max(relativeIndex, 0) + groupedMatch.length,
    match: groupedMatch
  };
}

function looksLikePhoneNumber(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  return digits.length >= 10 && digits.length <= 15;
}

function buildWhyList(rule: RuleDefinition, context: string, confidence: number, spanLength: number): string[] {
  const why = [rule.explanation];
  const loweredContext = context.toLowerCase();
  const keyword = rule.contextKeywords?.find((item) => loweredContext.includes(item.toLowerCase()));

  if (keyword) {
    why.push(`Nearby context references "${keyword}", which increases confidence that this is live data.`);
  }

  if (spanLength >= 24) {
    why.push("The match length is long enough to look like a real credential rather than a short placeholder.");
  }

  if (confidence >= 90) {
    why.push("Confidence is high enough that PromptProtect treats this as likely production-sensitive.");
  }

  return why.slice(0, 3);
}

function calculateConfidence(rule: RuleDefinition, match: string, context: string): number {
  let confidence = rule.baseConfidence;
  const loweredContext = context.toLowerCase();

  for (const keyword of rule.contextKeywords ?? []) {
    if (loweredContext.includes(keyword.toLowerCase())) {
      confidence += 6;
    }
  }

  if (/[=:]/.test(context) && /(key|token|secret|authorization|password|bearer)/i.test(context)) {
    confidence += 8;
  }

  if (rule.category === "secret" && match.length >= 24) {
    confidence += 4;
  }

  if (rule.captureGroup !== undefined) {
    confidence += 4;
  }

  return Math.max(1, Math.min(99, confidence));
}

function confidenceLabelForScore(score: number): ConfidenceLabel {
  if (score >= 80) {
    return "high";
  }

  if (score >= 60) {
    return "medium";
  }

  return "low";
}

function severityForFinding(category: FindingCategory, confidence: number): FindingSeverity {
  if (category === "secret" && confidence >= 90) {
    return "critical";
  }

  if (category === "secret") {
    return "high";
  }

  return confidence >= 82 ? "high" : "medium";
}

export function buildAllowFingerprint(ruleId: string, match: string): string {
  const normalized = match.trim().replace(/\s+/g, " ");
  return `${ruleId}:${normalized}`;
}

function isSuppressedByAllowlist(finding: DetectionFinding, settings: PromptProtectSettings, hostname?: string): boolean {
  if (hostname) {
    const exactMatch = settings.exactAllowRules.some(
      (rule) =>
        (!rule.expiresAt || Date.parse(rule.expiresAt) > Date.now()) &&
        rule.hostname === hostname &&
        rule.ruleId === finding.ruleId &&
        rule.matchFingerprint === finding.allowFingerprint
    );

    if (exactMatch) {
      return true;
    }
  }

  return settings.workspaceAllowlist
    .filter((pattern) => pattern.enabled)
    .some((pattern) => {
      try {
        const regex = new RegExp(pattern.pattern, ensureRuntimeFlags(pattern.flags).replace("d", ""));
        return regex.test(finding.match) || regex.test(finding.context);
      } catch {
        return false;
      }
    });
}

function collectMatches(
  text: string,
  rule: RuleDefinition,
  settings: PromptProtectSettings,
  options?: DetectionOptions
): DetectionFinding[] {
  const matches: DetectionFinding[] = [];
  const regex = new RegExp(rule.pattern, ensureRuntimeFlags(rule.flags));
  let result: RegExpExecArray | null;

  while ((result = regex.exec(text)) !== null) {
    const span = extractMatchSpan(result, rule.captureGroup);

    if (!span.match) {
      regex.lastIndex += 1;
      continue;
    }

    if (rule.id === "phone" && !looksLikePhoneNumber(span.match)) {
      continue;
    }

    const context = getContextWindow(text, span.start, span.end);
    const confidence = calculateConfidence(rule, span.match, context);
    const finding: DetectionFinding = {
      id: crypto.randomUUID(),
      ruleId: rule.id,
      label: rule.label,
      category: rule.category,
      severity: severityForFinding(rule.category, confidence),
      source: rule.source,
      start: span.start,
      end: span.end,
      match: span.match,
      snippet: span.match.replace(/\s+/g, " ").trim(),
      placeholder: rule.placeholder,
      explanation: rule.explanation,
      confidence,
      confidenceLabel: confidenceLabelForScore(confidence),
      why: buildWhyList(rule, context, confidence, span.match.length),
      context,
      allowFingerprint: buildAllowFingerprint(rule.id, span.match),
      origin: options?.origin ?? "composer"
    };

    if (!options?.ignoreAllowRules && isSuppressedByAllowlist(finding, settings, options?.hostname)) {
      continue;
    }

    matches.push(finding);
  }

  return matches;
}

function scoreFinding(finding: DetectionFinding): number {
  const severityWeight = finding.severity === "critical" ? 2000 : finding.severity === "high" ? 1000 : 100;
  const span = finding.end - finding.start;
  return severityWeight + finding.confidence + span;
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

function buildSummary(findings: DetectionFinding[]): DetectionResult["summary"] {
  const secrets = findings.filter((finding) => finding.category === "secret").length;
  const pii = findings.filter((finding) => finding.category === "pii").length;
  const secretWeight = secrets >= pii ? "secret" : "pii";

  return {
    total: findings.length,
    secrets,
    pii,
    critical: findings.filter((finding) => finding.severity === "critical").length,
    highConfidence: findings.filter((finding) => finding.confidenceLabel === "high").length,
    ruleLabels: Array.from(new Set(findings.map((finding) => finding.label))),
    topCategory: findings.length ? secretWeight : null
  };
}

export function detectSensitiveContent(
  text: string,
  settings: PromptProtectSettings,
  options?: DetectionOptions
): DetectionResult {
  const threshold = getStrictnessThreshold(settings, options);
  const findings = buildRuntimeRules(settings)
    .flatMap((rule) => collectMatches(text, rule, settings, options))
    .filter((finding) => finding.confidence >= threshold);
  const deduped = dedupeOverlaps(findings);

  return {
    findings: deduped,
    summary: buildSummary(deduped)
  };
}
