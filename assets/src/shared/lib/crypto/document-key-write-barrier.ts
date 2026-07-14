const blockedDocuments = new Set<string>();
const activeWrites = new Map<string, number>();
const drainWaiters = new Map<string, Set<() => void>>();

export async function runDocumentOfflineWrite<T>(
  documentId: string,
  write: () => Promise<T>,
): Promise<T | undefined> {
  if (blockedDocuments.has(documentId)) return undefined;
  activeWrites.set(documentId, (activeWrites.get(documentId) ?? 0) + 1);
  try {
    return await write();
  } finally {
    const remaining = (activeWrites.get(documentId) ?? 1) - 1;
    if (remaining > 0) {
      activeWrites.set(documentId, remaining);
    } else {
      activeWrites.delete(documentId);
      for (const resolve of drainWaiters.get(documentId) ?? []) resolve();
      drainWaiters.delete(documentId);
    }
  }
}

export async function beginDocumentOfflineWipe(documentId: string): Promise<() => void> {
  blockedDocuments.add(documentId);
  if ((activeWrites.get(documentId) ?? 0) > 0) {
    await new Promise<void>((resolve) => {
      const waiters = drainWaiters.get(documentId) ?? new Set<() => void>();
      waiters.add(resolve);
      drainWaiters.set(documentId, waiters);
    });
  }
  return () => blockedDocuments.delete(documentId);
}
