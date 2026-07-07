export type ClientLogContext = unknown;

function serializeClientLogContext(context: ClientLogContext): ClientLogContext {
  if (context instanceof Error) {
    return {
      name: context.name,
      message: context.message,
      code: "code" in context ? (context as { code?: unknown }).code : undefined,
      stack: context.stack,
    };
  }
  if (Array.isArray(context)) return context.map(serializeClientLogContext);
  if (typeof context !== "object" || context === null) return context;
  return Object.fromEntries(
    Object.entries(context).map(([key, value]) => [key, serializeClientLogContext(value)]),
  );
}

function emitClientLog(level: "warn" | "error", message: string, context?: ClientLogContext): void {
  if (typeof window === "undefined") return;

  window.dispatchEvent(
    new CustomEvent("refmd:client-log", {
      detail: {
        level,
        message,
        context: serializeClientLogContext(context),
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
