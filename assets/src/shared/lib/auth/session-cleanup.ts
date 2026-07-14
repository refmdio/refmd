type SessionCleanupScope = "all" | "secure";

interface BeforeCleanupEntry {
  callback: () => Promise<void> | void;
  callbackId: number;
  scope: SessionCleanupScope;
  order: number;
}

export interface SessionCleanupFailure {
  callbackId: number;
  reason: "rejected";
}

export interface SessionCleanupResult {
  failures: SessionCleanupFailure[];
}

const beforeCleanupCallbacks = new Set<BeforeCleanupEntry>();
const cleanupCallbacks = new Set<() => void>();
let nextBeforeCleanupCallbackId = 1;

export function registerBeforeSessionCleanup(
  callback: () => Promise<void> | void,
  options: { scope?: SessionCleanupScope; order?: number } = {},
): () => void {
  const entry: BeforeCleanupEntry = {
    callback,
    callbackId: nextBeforeCleanupCallbackId++,
    scope: options.scope ?? "all",
    order: options.order ?? 0,
  };
  beforeCleanupCallbacks.add(entry);
  return () => beforeCleanupCallbacks.delete(entry);
}

export function registerSessionCleanup(callback: () => void): void {
  cleanupCallbacks.add(callback);
}

export async function runBeforeSessionCleanup(options: {
  secure: boolean;
}): Promise<SessionCleanupResult> {
  const entries = [...beforeCleanupCallbacks]
    .filter((entry) => options.secure || entry.scope === "all")
    .sort((left, right) => left.order - right.order);
  const orders = [...new Set(entries.map((entry) => entry.order))];
  const failures: SessionCleanupFailure[] = [];

  for (const order of orders) {
    const results = await Promise.all(
      entries
        .filter((entry) => entry.order === order)
        .map((entry) => runBeforeCleanupCallback(entry)),
    );
    failures.push(...results.filter((result) => result !== null));
  }

  return { failures };
}

function runBeforeCleanupCallback(
  entry: BeforeCleanupEntry,
): Promise<SessionCleanupFailure | null> {
  return Promise.resolve()
    .then(() => entry.callback())
    .then(
      () => null,
      () => ({ callbackId: entry.callbackId, reason: "rejected" as const }),
    );
}

export function runSessionCleanup(): void {
  for (const callback of cleanupCallbacks) {
    callback();
  }
}
