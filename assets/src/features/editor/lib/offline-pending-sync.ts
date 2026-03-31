import {
  acquireDocumentState,
  getDocumentState,
  releaseDocumentState,
  type DocumentState,
} from "./document-state-cache";
import { initializeDocumentSync } from "./document-sync";
import { restoreDocumentStateFromCache } from "./document-offline-init";
import { offlineMode } from "@/shared/lib/offline/offline-state";
import {
  getAllPendingChanges,
  getDocumentCache,
  getOfflineCreated,
  getOfflineDocumentMeta,
  getPendingChanges,
} from "@/shared/lib/offline/offline-store";

const PENDING_SYNC_TIMEOUT_MS = 20_000;
const PENDING_SYNC_POLL_MS = 200;

const inFlightSyncs = new Map<string, Promise<void>>();

interface PendingSyncTarget {
  documentId: string;
  workspaceId: string;
  isOfflineCreated: boolean;
}

export async function syncPendingDocuments(workspaceId?: string): Promise<void> {
  if (offlineMode()) return;

  const pendingEntries = await getAllPendingChanges();
  if (pendingEntries.length === 0) return;

  for (const entry of pendingEntries) {
    const target = await resolvePendingTarget(entry.documentId);
    if (!target || target.isOfflineCreated) continue;
    if (workspaceId && target.workspaceId !== workspaceId) continue;

    try {
      await syncPendingDocument(target.documentId, target.workspaceId);
    } catch (error) {
      console.warn("[offline-sync] Failed to sync pending document:", target.documentId, error);
    }
  }
}

async function syncPendingDocument(documentId: string, workspaceId: string): Promise<void> {
  const existing = inFlightSyncs.get(documentId);
  if (existing) {
    await existing;
    return;
  }

  const promise = doSyncPendingDocument(documentId, workspaceId).finally(() => {
    inFlightSyncs.delete(documentId);
  });

  inFlightSyncs.set(documentId, promise);
  await promise;
}

async function doSyncPendingDocument(documentId: string, workspaceId: string): Promise<void> {
  if (offlineMode()) return;

  const existingState = getDocumentState(documentId);
  if (existingState) {
    await syncExistingState(documentId, existingState);
    return;
  }

  await acquireDocumentState(documentId, workspaceId);
  const state = getDocumentState(documentId);
  if (!state) return;

  try {
    const restored = await restoreDocumentStateFromCache(documentId, workspaceId, state);
    if (!restored) return;

    state.error = null;
    state.readOnly = false;
    state.loadedFromOfflineCache = false;
    state._headlessSync = true;
    state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
    await state.initPromise;
    state.autoSync?.notifyLocalEdit();
    await waitForPendingChangesToClear(documentId);
  } finally {
    state._headlessSync = false;
    releaseDocumentState(documentId);
  }
}

async function syncExistingState(documentId: string, state: DocumentState): Promise<void> {
  if (state.loadedFromOfflineCache || state.initPromise) {
    return;
  }

  if (!state.initialized || state.readOnly || state.error) {
    return;
  }

  state.autoSync?.notifyLocalEdit();
  await waitForPendingChangesToClear(documentId);
}

async function waitForPendingChangesToClear(documentId: string): Promise<void> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < PENDING_SYNC_TIMEOUT_MS) {
    if (offlineMode()) return;

    const pending = await getPendingChanges(documentId);
    if (!pending) return;

    await new Promise((resolve) => setTimeout(resolve, PENDING_SYNC_POLL_MS));
  }
}

async function resolvePendingTarget(documentId: string): Promise<PendingSyncTarget | null> {
  const offlineCreated = await getOfflineCreated(documentId);
  if (offlineCreated) {
    return {
      documentId,
      workspaceId: offlineCreated.workspaceId,
      isOfflineCreated: true,
    };
  }

  const cacheEntry = await getDocumentCache(documentId);
  if (cacheEntry) {
    return {
      documentId,
      workspaceId: cacheEntry.workspaceId,
      isOfflineCreated: false,
    };
  }

  const meta = await getOfflineDocumentMeta(documentId);
  if (meta) {
    return {
      documentId,
      workspaceId: meta.workspaceId,
      isOfflineCreated: false,
    };
  }

  return null;
}
