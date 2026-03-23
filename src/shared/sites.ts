import type { SupportedSite } from "./types";

export const SUPPORTED_SITES: SupportedSite[] = [
  {
    id: "chatgpt",
    label: "ChatGPT",
    hostnames: ["chatgpt.com", "chat.openai.com"],
    composerSelectors: [
      "#prompt-textarea",
      "textarea[placeholder*='Message']",
      "div[contenteditable='true'][data-testid='composer-text-input']",
      "div[contenteditable='true'][role='textbox']"
    ],
    sendButtonSelectors: [
      "button[data-testid='send-button']",
      "button[aria-label*='Send prompt' i]",
      "button[aria-label*='Send message' i]",
      "button[title*='Send' i]"
    ]
  },
  {
    id: "claude",
    label: "Claude",
    hostnames: ["claude.ai"],
    composerSelectors: [
      "div[contenteditable='true'][enterkeyhint='send']",
      "div[contenteditable='true'][data-testid='chat-input']",
      "div[contenteditable='true'][role='textbox']",
      "textarea"
    ],
    sendButtonSelectors: [
      "button[aria-label*='Send message' i]",
      "button[aria-label*='Send Message' i]",
      "button[title*='Send' i]"
    ]
  },
  {
    id: "gemini",
    label: "Gemini",
    hostnames: ["gemini.google.com"],
    composerSelectors: [
      "div.ql-editor[contenteditable='true']",
      "div[contenteditable='true'][role='textbox']",
      "textarea"
    ],
    sendButtonSelectors: [
      "button[aria-label*='Send message' i]",
      "button[aria-label*='Send' i]",
      "button[mattooltip*='Send' i]"
    ]
  }
];

const FALLBACK_COMPOSER_SELECTORS = [
  "textarea",
  "div[contenteditable='true'][role='textbox']",
  "div[contenteditable='true'][aria-label]"
];

const FALLBACK_SEND_BUTTON_SELECTORS = [
  "button[aria-label*='Send' i]",
  "button[title*='Send' i]",
  "button[data-testid*='send' i]",
  "button[type='submit']"
];

export function getSupportedSiteForHostname(hostname: string): SupportedSite | undefined {
  return SUPPORTED_SITES.find((site) => site.hostnames.includes(hostname));
}

export function getComposerSelectorsForHostname(hostname: string): string[] {
  const site = getSupportedSiteForHostname(hostname);
  return site ? [...site.composerSelectors, ...FALLBACK_COMPOSER_SELECTORS] : FALLBACK_COMPOSER_SELECTORS;
}

export function getSendButtonSelectorsForHostname(hostname: string): string[] {
  const site = getSupportedSiteForHostname(hostname);
  return site ? [...site.sendButtonSelectors, ...FALLBACK_SEND_BUTTON_SELECTORS] : FALLBACK_SEND_BUTTON_SELECTORS;
}

