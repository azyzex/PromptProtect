import { getComposerSelectorsForHostname, getSendButtonSelectorsForHostname } from "../shared/sites";

export type ComposerElement = HTMLTextAreaElement | HTMLInputElement | HTMLElement;

function uniqueElements<T>(elements: T[]): T[] {
  return Array.from(new Set(elements));
}

function isVisible(element: HTMLElement): boolean {
  const styles = window.getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  return styles.visibility !== "hidden" && styles.display !== "none" && rect.width > 0 && rect.height > 0;
}

function isIgnoredNode(element: HTMLElement, ignoredSelector: string): boolean {
  return Boolean(element.closest(ignoredSelector));
}

function isComposerCandidate(element: HTMLElement, hostname: string, ignoredSelector: string): boolean {
  if (!isVisible(element) || isIgnoredNode(element, ignoredSelector)) {
    return false;
  }

  return element.matches(getComposerSelectorsForHostname(hostname).join(", "));
}

export function resolveComposer(target: EventTarget | Element | null, hostname: string, ignoredSelector: string): ComposerElement | null {
  if (target instanceof Element) {
    const selectors = getComposerSelectorsForHostname(hostname);

    for (const selector of selectors) {
      const candidate = target.closest(selector);

      if (candidate instanceof HTMLElement && isVisible(candidate) && !isIgnoredNode(candidate, ignoredSelector)) {
        return candidate as ComposerElement;
      }
    }
  }

  const activeElement = document.activeElement;

  if (activeElement instanceof HTMLElement && isComposerCandidate(activeElement, hostname, ignoredSelector)) {
    return activeElement as ComposerElement;
  }

  return findPreferredComposer(hostname, ignoredSelector);
}

export function findPreferredComposer(hostname: string, ignoredSelector: string): ComposerElement | null {
  const selectors = getComposerSelectorsForHostname(hostname);
  const candidates = selectors.flatMap((selector) => Array.from(document.querySelectorAll<HTMLElement>(selector)));
  const visible = uniqueElements(candidates).filter((candidate) => isComposerCandidate(candidate, hostname, ignoredSelector));

  visible.sort((left, right) => {
    const leftRect = left.getBoundingClientRect();
    const rightRect = right.getBoundingClientRect();
    return rightRect.bottom - leftRect.bottom || rightRect.width * rightRect.height - leftRect.width * leftRect.height;
  });

  return (visible[0] as ComposerElement | undefined) ?? null;
}

export function resolveSendButton(target: EventTarget | null, hostname: string, ignoredSelector: string): HTMLElement | null {
  if (!(target instanceof Element)) {
    return null;
  }

  const selectors = getSendButtonSelectorsForHostname(hostname);

  for (const selector of selectors) {
    const candidate = target.closest(selector);

    if (candidate instanceof HTMLElement && isVisible(candidate) && !candidate.hasAttribute("disabled") && !isIgnoredNode(candidate, ignoredSelector)) {
      return candidate;
    }
  }

  return null;
}

function distanceToComposer(buttonRect: DOMRect, composerRect: DOMRect): number {
  const horizontal = Math.abs(buttonRect.left - composerRect.right);
  const vertical = Math.abs(buttonRect.top - composerRect.top);
  return horizontal + vertical;
}

export function findNearestSendButton(composer: HTMLElement, hostname: string, ignoredSelector: string): HTMLElement | null {
  const selectors = getSendButtonSelectorsForHostname(hostname);
  const candidates = selectors.flatMap((selector) => Array.from(document.querySelectorAll<HTMLElement>(selector)));
  const visible = uniqueElements(candidates).filter(
    (candidate) => isVisible(candidate) && !candidate.hasAttribute("disabled") && !isIgnoredNode(candidate, ignoredSelector)
  );

  if (!visible.length) {
    return null;
  }

  const composerRect = composer.getBoundingClientRect();

  visible.sort((left, right) => {
    const leftDistance = distanceToComposer(left.getBoundingClientRect(), composerRect);
    const rightDistance = distanceToComposer(right.getBoundingClientRect(), composerRect);
    return leftDistance - rightDistance;
  });

  return visible[0] ?? null;
}

export function findAnySendButton(hostname: string): HTMLElement | null {
  const selectors = getSendButtonSelectorsForHostname(hostname);

  for (const selector of selectors) {
    const candidate = document.querySelector<HTMLElement>(selector);

    if (candidate && isVisible(candidate) && !candidate.hasAttribute("disabled")) {
      return candidate;
    }
  }

  return null;
}

export function readComposerText(composer: ComposerElement): string {
  if (composer instanceof HTMLTextAreaElement || composer instanceof HTMLInputElement) {
    return composer.value;
  }

  return composer.innerText.replace(/\u00a0/g, " ");
}

export function focusComposer(composer: ComposerElement) {
  if (composer instanceof HTMLElement) {
    composer.focus();
  }
}

function textToNodes(value: string): Node[] {
  const lines = value.split("\n");
  const nodes: Node[] = [];

  lines.forEach((line, index) => {
    if (index > 0) {
      nodes.push(document.createElement("br"));
    }

    nodes.push(document.createTextNode(line));
  });

  return nodes;
}

export function writeComposerText(composer: ComposerElement, text: string) {
  if (composer instanceof HTMLTextAreaElement || composer instanceof HTMLInputElement) {
    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(composer), "value");

    if (descriptor?.set) {
      descriptor.set.call(composer, text);
    } else {
      composer.value = text;
    }

    composer.dispatchEvent(new Event("input", { bubbles: true }));
    composer.dispatchEvent(new Event("change", { bubbles: true }));
    return;
  }

  composer.focus();
  const selection = window.getSelection();

  if (selection) {
    const range = document.createRange();
    range.selectNodeContents(composer);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  const inserted = typeof document.execCommand === "function" ? document.execCommand("insertText", false, text) : false;

  if (!inserted) {
    composer.replaceChildren(...textToNodes(text));
  }

  composer.dispatchEvent(
    new InputEvent("input", {
      bubbles: true,
      inputType: "insertText",
      data: text
    })
  );
}
