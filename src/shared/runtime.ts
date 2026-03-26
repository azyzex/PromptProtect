import type { AppendLogPayload, LogEntry, PromptProtectSettings, RuntimeRequest } from "./types";

export function sendMessage<T>(message: RuntimeRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response: T) => {
      const error = chrome.runtime.lastError;

      if (error) {
        reject(new Error(error.message));
        return;
      }

      if (
        response &&
        typeof response === "object" &&
        "error" in (response as Record<string, unknown>) &&
        typeof (response as Record<string, unknown>).error === "string"
      ) {
        reject(new Error((response as Record<string, unknown>).error as string));
        return;
      }

      resolve(response);
    });
  });
}

export const runtimeApi = {
  getSettings(): Promise<PromptProtectSettings> {
    return sendMessage<PromptProtectSettings>({ type: "promptprotect:get-settings" });
  },
  saveSettings(settings: PromptProtectSettings): Promise<PromptProtectSettings> {
    return sendMessage<PromptProtectSettings>({
      type: "promptprotect:save-settings",
      settings
    });
  },
  getLogs(): Promise<LogEntry[]> {
    return sendMessage<LogEntry[]>({ type: "promptprotect:get-logs" });
  },
  clearLogs(): Promise<LogEntry[]> {
    return sendMessage<LogEntry[]>({ type: "promptprotect:clear-logs" });
  },
  appendLog(payload: AppendLogPayload): Promise<LogEntry> {
    return sendMessage<LogEntry>({ type: "promptprotect:append-log", payload });
  }
};
