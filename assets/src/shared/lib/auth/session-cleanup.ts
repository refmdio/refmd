type SessionCleanupScope = "all" | "secure";

interface BeforeCleanupEntry {
  callback: () => Promise<void> | void;
  scope: SessionCleanupScope;
}

const beforeCleanupCallbacks = new Set<BeforeCleanupEntry>();
const cleanupCallbacks = new Set<() => void>();

export function registerBeforeSessionCleanup(
  callback: () => Promise<void> | void,
  options: { scope?: SessionCleanupScope } = {},
): () => void {
  const entry: BeforeCleanupEntry = {
    callback,
    scope: options.scope ?? "all",
  };
  beforeCleanupCallbacks.add(entry);
  return () => beforeCleanupCallbacks.delete(entry);
}

export function registerSessionCleanup(callback: () => void): void {
  cleanupCallbacks.add(callback);
}

export async function runBeforeSessionCleanup(options: { secure: boolean }): Promise<void> {
  await Promise.allSettled(
    [...beforeCleanupCallbacks]
      .filter((entry) => options.secure || entry.scope === "all")
      .map((entry) => entry.callback()),
  );
}

export function runSessionCleanup(): void {
  for (const callback of cleanupCallbacks) {
    callback();
  }
}
