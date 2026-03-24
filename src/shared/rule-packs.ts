import type { RulePack } from "./types";

export const STARTER_RULE_PACKS: RulePack[] = [
  {
    name: "Engineering Demo Pack",
    description: "Sample company-style token formats for staging, internal demos, and sandbox credentials.",
    patterns: [
      {
        label: "Demo service token",
        pattern: "\\bdemo_[A-Za-z0-9]{18,}\\b",
        flags: "g",
        category: "secret",
        explanation: "Matches long demo service tokens that still should not be pasted into public LLM tools.",
        placeholder: "<DEMO_SERVICE_TOKEN>"
      },
      {
        label: "Sandbox access token",
        pattern: "\\bsbx_[A-Za-z0-9_-]{20,}\\b",
        flags: "g",
        category: "secret",
        explanation: "Captures sandbox API tokens often shared during internal development.",
        placeholder: "<SANDBOX_ACCESS_TOKEN>"
      },
      {
        label: "Internal customer email",
        pattern: "\\b[A-Z0-9._%+-]+@examplecorp\\.internal\\b",
        flags: "gi",
        category: "pii",
        explanation: "Catches internal customer or employee email addresses for company-specific domains.",
        placeholder: "<INTERNAL_EMAIL>"
      }
    ]
  }
];
