const cleanupCallbacks = new Set<() => void>();

export function registerSessionCleanup(callback: () => void): void {
  cleanupCallbacks.add(callback);
}

export function runSessionCleanup(): void {
  for (const callback of cleanupCallbacks) {
    callback();
  }
}
