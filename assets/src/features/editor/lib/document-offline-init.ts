import * as Y from "yjs";
import type { DocumentState } from "./document-state-cache";
import { startAutoSync } from "./auto-sync";
import { recoverDocumentFromCache, startPeriodicFlush } from "@/shared/lib/offline/cache-manager";
import { onOfflineModeChange, setWsConnected } from "@/shared/lib/offline/offline-state";
import { isSocketConnected } from "@/shared/lib/ws/phoenix-channel";
import { DocumentSyncError } from "./document-sync-error";

function teardownOfflineRuntime(state: DocumentState): void {
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  if (state.offlineFlushCleanup) {
    state.offlineFlushCleanup();
    state.offlineFlushCleanup = null;
  }
  if (state.offlineResumeCleanup) {
    state.offlineResumeCleanup();
    state.offlineResumeCleanup = null;
  }
}

async function resumeDocumentFromServer(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  teardownOfflineRuntime(state);
  state.loadedFromOfflineCache = false;
  state.initialized = false;
  state.initPromise = null;
  state.error = null;

  const { initializeDocumentSync } = await import("./document-sync");

  try {
    state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
    await state.initPromise;
    return;
  } catch (err) {
    state.initPromise = null;

    if (err instanceof DocumentSyncError && err.code === "unauthorized") {
      const { requestReauth } = await import("./document-state-cache");
      await requestReauth(documentId);

      try {
        state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
        await state.initPromise;
        return;
      } catch (retryErr) {
        state.initPromise = null;
        if (retryErr instanceof DocumentSyncError && retryErr.code === "server_unreachable") {
          activateOfflineEditingSession(documentId, workspaceId, state, true);
          return;
        }
        state.error = retryErr instanceof Error ? retryErr.message : String(retryErr);
        return;
      }
    }

    if (err instanceof DocumentSyncError && err.code === "server_unreachable") {
      activateOfflineEditingSession(documentId, workspaceId, state, true);
      return;
    }

    state.error = err instanceof Error ? err.message : String(err);
  }
}

function activateOfflineEditingSession(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  forceOfflineMode = false,
): void {
  state.initialized = true;
  state.loadedFromOfflineCache = true;
  state.error = null;

  if (forceOfflineMode || !isSocketConnected()) {
    setWsConnected(false);
  }

  state.autoSync = startAutoSync(documentId, state);
  state.offlineFlushCleanup = startPeriodicFlush(documentId, workspaceId, state);
  state.offlineResumeCleanup = onOfflineModeChange((isOffline) => {
    if (!isOffline && state.loadedFromOfflineCache) {
      void resumeDocumentFromServer(documentId, workspaceId, state);
    }
  });
}

export async function restoreDocumentStateFromCache(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<boolean> {
  const recovered = await recoverDocumentFromCache(documentId);
  if (!recovered) return false;

  teardownOfflineRuntime(state);

  const recoveredState = Y.encodeStateAsUpdate(recovered.yDoc);
  Y.applyUpdate(state.yDoc, recoveredState, "remote");
  recovered.yDoc.destroy();

  state.activeSnapshotId = recovered.confirmedSnapshotId || null;
  state.confirmedClocks = recovered.confirmedClocks;
  state.knownClocks = { ...recovered.confirmedClocks };
  state.latestVersion = recovered.confirmedVersion;
  state.keyVersion = recovered.keyVersion;
  state.dekResolved = true;
  state.workspaceId = workspaceId;
  state.error = null;
  state.readOnly = false;
  state.initialized = false;
  state.loadedFromOfflineCache = false;
  state.lastSavedState = recovered.confirmedBaseState ?? null;
  state._cachedConfirmedStateVector = recovered.confirmedStateVector ?? null;

  // Restore proof chain state from persisted pin for reconnect validation
  const { getDocumentStatePin } = await import("@/shared/lib/anti-rollback/document-state-pins");
  const pin = await getDocumentStatePin(documentId).catch(() => null);
  if (pin) {
    state.snapshotProofHash = pin.latestSnapshotProofHash;
    state.snapshotCiphertextHash = pin.latestSnapshotCiphertextHash;
  }

  return true;
}

export async function initializeDocumentFromCache(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<boolean> {
  const restored = await restoreDocumentStateFromCache(documentId, workspaceId, state);
  if (!restored) return false;

  activateOfflineEditingSession(documentId, workspaceId, state);
  return true;
}
