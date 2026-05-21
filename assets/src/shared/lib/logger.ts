export type ClientLogContext = Record<string, unknown> | readonly unknown[] | unknown;

function emitClientLog(level: "warn" | "error", message: string, context?: ClientLogContext): void {
  if (typeof window === "undefined") return;

  window.dispatchEvent(
    new CustomEvent("refmd:client-log", {
      detail: {
        level,
        message,
        context,
        at: new Date().toISOString(),
      },
    }),
  );
}

export function clientWarn(message: string, context?: ClientLogContext): void {
  emitClientLog("warn", message, context);
}

export function clientError(message: string, context?: ClientLogContext): void {
  emitClientLog("error", message, context);
}
