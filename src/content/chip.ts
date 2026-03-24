import type { ComposerElement } from "./dom";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function createInlineChipController(rootId: string) {
  let chipTimer: number | null = null;

  function hide() {
    if (chipTimer) {
      window.clearTimeout(chipTimer);
      chipTimer = null;
    }

    document.getElementById(rootId)?.remove();
  }

  function show(anchor: ComposerElement, message: string) {
    hide();

    const target = anchor instanceof HTMLElement ? anchor : null;

    if (!target) {
      return;
    }

    const host = document.createElement("div");
    host.id = rootId;
    const shadowRoot = host.attachShadow({ mode: "open" });
    const rect = target.getBoundingClientRect();
    const width = Math.min(360, Math.max(220, rect.width));
    const top = Math.min(window.innerHeight - 88, rect.top + rect.height + 10);
    const left = Math.min(window.innerWidth - width - 12, Math.max(12, rect.left));

    Object.assign(host.style, {
      position: "fixed",
      top: `${top}px`,
      left: `${left}px`,
      width: `${width}px`,
      zIndex: "2147483646"
    });

    shadowRoot.innerHTML = `
      <style>
        * {
          box-sizing: border-box;
          font-family: "Aptos", "Segoe UI Variable Display", "SF Pro Display", system-ui, sans-serif;
        }

        .chip {
          display: flex;
          gap: 12px;
          align-items: flex-start;
          padding: 12px 14px;
          border-radius: 18px;
          color: white;
          background: linear-gradient(145deg, rgba(16, 20, 30, 0.96), rgba(15, 118, 110, 0.96));
          border: 1px solid rgba(255, 255, 255, 0.1);
          box-shadow: 0 18px 38px rgba(16, 20, 30, 0.3);
        }

        .badge {
          flex-shrink: 0;
          padding: 7px 10px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.12);
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
        }

        p {
          margin: 0;
          line-height: 1.45;
          color: rgba(255, 255, 255, 0.86);
          font-size: 13px;
        }
      </style>
      <div class="chip">
        <span class="badge">Heads up</span>
        <p>${escapeHtml(message)}</p>
      </div>
    `;

    document.documentElement.appendChild(host);
    chipTimer = window.setTimeout(() => hide(), 5600);
  }

  return { show, hide };
}
