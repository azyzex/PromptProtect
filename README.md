# PromptProtect

PromptProtect is a Chrome extension that helps stop accidental leaks to web-based LLM chat tools. It watches supported chat composers locally, detects likely secrets or basic PII before send, and forces a quick review step with redaction.

## MVP in this repo

- Small default site scope: ChatGPT, Claude, and Gemini web UIs
- Local pattern detection for:
  - OpenAI-style keys
  - AWS access keys
  - GitHub tokens
  - JWTs
  - PEM private key blocks
  - Emails and phone numbers
- On-send interception with a review modal, highlighted matches, and `Redact & Send` / `Cancel`
- Local-only event logs that store counts and rule labels, not raw sensitive text
- Premium popup dashboard for toggles, custom regex rules, and recent findings

## Quick Start

1. Install dependencies:

```bash
npm install
```

2. Build the extension:

```bash
npm run build
```

3. Load it in Chrome:

- Open `chrome://extensions`
- Enable `Developer mode`
- Click `Load unpacked`
- Select the repo's `dist` folder

4. Open the PromptProtect popup:

- Click the PromptProtect toolbar action in Chrome

## Git Setup

This workspace is initialized on the `main` branch and wired to:

```text
https://github.com/azyzex/PromptProtect.git
```

If you want to publish the local work once your Git identity is configured:

```bash
git add .
git commit -m "Initial PromptProtect MVP"
git push -u origin main
```

## Project Structure

- `src/content`: composer detection, send interception, review modal
- `src/background`: storage and local telemetry coordination
- `src/sidepanel`: settings, custom rules, and finding history UI
- `src/shared`: detection engine, redaction helpers, site definitions, shared types
- `static`: `manifest.json` and side panel HTML/CSS

## Notes

- PromptProtect only runs on a small manifest allowlist to keep permissions tight.
- Custom rules are local regex patterns stored in extension storage.
- The current allowlist UI lets you toggle supported hosts on and off. Expanding beyond those hosts requires updating the manifest host permissions.
