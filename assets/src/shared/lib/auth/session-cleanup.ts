type SessionCleanupScope = "all" | "secure";

interface BeforeCleanupEntry {
  callback: () => Promise<void> | void;
  scope: SessionCleanupScope;
  order: number;
}

const beforeCleanupCallbacks = new Set<BeforeCleanupEntry>();
const cleanupCallbacks = new Set<() => void>();
const BEFORE_CLEANUP_CALLBACK_TIMEOUT_MS = 5_000;

export function registerBeforeSessionCleanup(
  callback: () => Promise<void> | void,
  options: { scope?: SessionCleanupScope; order?: number } = {},
): () => void {
  const entry: BeforeCleanupEntry = {
    callback,
    scope: options.scope ?? "all",
    order: options.order ?? 0,
  };
  beforeCleanupCallbacks.add(entry);
  return () => beforeCleanupCallbacks.delete(entry);
}

export function registerSessionCleanup(callback: () => void): void {
  cleanupCallbacks.add(callback);
}

export async function runBeforeSessionCleanup(options: { secure: boolean }): Promise<void> {
  const entries = [...beforeCleanupCallbacks]
    .filter((entry) => options.secure || entry.scope === "all")
    .sort((left, right) => left.order - right.order);
  const orders = [...new Set(entries.map((entry) => entry.order))];
  for (const order of orders) {
    await Promise.allSettled(
      entries
        .filter((entry) => entry.order === order)
        .map((entry) => runBeforeCleanupCallback(entry)),
    );
  }
}

async function runBeforeCleanupCallback(entry: BeforeCleanupEntry): Promise<void> {
  await Promise.race([
    Promise.resolve().then(() => entry.callback()),
    new Promise<void>((resolve) => {
      window.setTimeout(resolve, BEFORE_CLEANUP_CALLBACK_TIMEOUT_MS);
    }),
  ]);
}

export function runSessionCleanup(): void {
  for (const callback of cleanupCallbacks) {
    callback();
  }
}
