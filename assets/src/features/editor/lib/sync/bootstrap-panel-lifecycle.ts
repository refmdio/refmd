import { acquireDocumentState, getDocumentState } from "../../model/document-state/store";
import { releaseDocumentState } from "../../model/document-state/lifecycle";
import {
  requestReauth,
  requestShareReentry,
  setDocumentError,
} from "../../model/document-state/signals";
import { initializeDocumentSync } from "./initialize";
import { DocumentChannelError, DocumentSyncError } from "./error";
import { initializeDocumentFromCache, restoreDocumentStateFromCache } from "../offline/restore";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";
import { shouldPreferOfflineCache } from "@/shared/lib/offline/offline-state";
import { isInitCancelledError } from "./bootstrap-cancel";

const panelInitializationLocks = new Map<string, Promise<void>>();

interface DocumentPanelLifecycleState {
  setError: (value: string | null) => void;
  setHasWarmCachePreview: (value: boolean) => void;
  setIsAccessRevoked: (value: boolean) => void;
  setIsDocumentDeleted: (value: boolean) => void;
  setIsLoading: (value: boolean) => void;
  setIsOfflineCached: (value: boolean) => void;
}
function hasWarmCacheState(stateKey: string): boolean {
  const state = getDocumentState(stateKey);
  if (!state) return false;
  return (
    state.keyVersion > 0 ||
    state.activeSnapshotId !== null ||
    state._cachedConfirmedStateVector !== null ||
    state.loadedFromOfflineCache
  );
}
function isCancelledInitializationError(error: unknown): boolean {
  if (isInitCancelledError(error)) return true;
  return error instanceof Error && error.message.toLowerCase().includes("aborted");
}
export function initializeDocumentPanel(
  documentId: string,
  workspaceId: string | null,
  panelState: DocumentPanelLifecycleState,
  stateKey = documentId,
): () => void {
  if (!workspaceId) {
    panelState.setError("No workspace selected");
    panelState.setIsLoading(false);
    return () => {};
  }
  panelState.setIsLoading(true);
  panelState.setError(null);
  panelState.setIsOfflineCached(false);
  panelState.setIsAccessRevoked(false);
  panelState.setIsDocumentDeleted(false);
  panelState.setHasWarmCachePreview(false);
  let cancelled = false;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  const scheduleInitialRetry = (state: NonNullable<ReturnType<typeof getDocumentState>>) => {
    if (retryTimer || state.initialized) return;
    const delay = Math.max(getAuthTransportBackoffMs(), 1_000);
    state.error = null;
    panelState.setError(null);
    panelState.setIsLoading(false);
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (cancelled || state.initialized || state.initPromise) return;
      panelState.setIsLoading(true);
      state.error = null;
      const retryInitPromise = initializeDocumentSync(documentId, workspaceId, state);
      state.initPromise = retryInitPromise;
      retryInitPromise
        .then(() => {
          if (cancelled) return;
          panelState.setHasWarmCachePreview(false);
          panelState.setError(state.error);
          panelState.setIsOfflineCached(state.loadedFromOfflineCache);
        })
        .catch((retryErr) => {
          if (cancelled) return;
          if (state.initPromise === retryInitPromise) {
            state.initPromise = null;
          }
          if (retryErr instanceof DocumentSyncError && retryErr.code === "server_unreachable") {
            scheduleInitialRetry(state);
            return;
          }
          const retryMessage =
            retryErr instanceof Error ? retryErr.message : "Failed to load document";
          state.error = retryMessage;
          panelState.setError(retryMessage);
        })
        .finally(() => {
          if (state.initPromise === retryInitPromise && !state.initialized) {
            state.initPromise = null;
          }
          if (!cancelled) panelState.setIsLoading(false);
        });
    }, delay);
  };
  void (async () => {
    try {
      await acquireDocumentState(documentId, workspaceId, stateKey);
      const state = getDocumentState(stateKey);
      if (!state || cancelled) return;

      if (!state.initialized && shouldPreferOfflineCache()) {
        const recovered = await initializeDocumentFromCache(documentId, workspaceId, state);
        if (recovered && !cancelled) {
          panelState.setHasWarmCachePreview(false);
          panelState.setIsOfflineCached(true);
          panelState.setError(null);
          panelState.setIsLoading(false);
          return;
        }
      }

      if (!state.initialized && !state.initPromise) {
        let initializationLock = panelInitializationLocks.get(stateKey);
        if (!initializationLock) {
          initializationLock = (async () => {
            if (!state.initialized && !hasWarmCacheState(stateKey)) {
              try {
                const recovered = await restoreDocumentStateFromCache(
                  documentId,
                  workspaceId,
                  state,
                );
                if (recovered && !cancelled) {
                  panelState.setHasWarmCachePreview(true);
                  panelState.setIsLoading(false);
                }
              } catch {
                // Best-effort: warm preview is opportunistic
              }
            } else if (!state.initialized && hasWarmCacheState(stateKey) && !cancelled) {
              panelState.setHasWarmCachePreview(true);
              panelState.setIsLoading(false);
            }
            if (!state.initialized && !state.initPromise) {
              state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
            }
          })().finally(() => {
            if (panelInitializationLocks.get(stateKey) === initializationLock) {
              panelInitializationLocks.delete(stateKey);
            }
          });
          panelInitializationLocks.set(stateKey, initializationLock);
        }
        await initializationLock;
      } else if (!state.initialized && hasWarmCacheState(stateKey)) {
        panelState.setHasWarmCachePreview(true);
        panelState.setIsLoading(false);
      }
      if (!state.initialized && !state.initPromise) {
        state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
      }
      if (state.initPromise) {
        await state.initPromise;
      }
      if (cancelled) return;
      panelState.setHasWarmCachePreview(false);
      if (state.error) {
        panelState.setError(state.error);
      }
      if (state.loadedFromOfflineCache) {
        panelState.setIsOfflineCached(true);
      }
    } catch (err) {
      if (cancelled) return;
      const state = getDocumentState(stateKey);
      if (state && isCancelledInitializationError(err)) {
        if (state.initialized) {
          setDocumentError(stateKey, null);
          panelState.setError(null);
          panelState.setHasWarmCachePreview(false);
          panelState.setIsOfflineCached(state.loadedFromOfflineCache);
        }
        return;
      }
      const isSecurityFailure =
        err instanceof DocumentSyncError &&
        (err.code === "rollback_attack" || err.code === "verification_failed");
      const isAuthFailure = err instanceof DocumentSyncError && err.code === "unauthorized";
      const isServerUnreachable =
        err instanceof DocumentSyncError && err.code === "server_unreachable";
      const isAccessDenied =
        err instanceof DocumentChannelError &&
        (err.code === "not_a_member" || err.code === "permission_denied");
      const isDeleted = err instanceof DocumentChannelError && err.code === "document_not_found";
      panelState.setIsDocumentDeleted(isDeleted);
      if (state && isAuthFailure) {
        if (state.access.kind === "share") {
          requestShareReentry(stateKey);
          panelState.setIsLoading(false);
          return;
        }

        try {
          await requestReauth(stateKey);
          if (cancelled) return;
          state.error = null;
          state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
          await state.initPromise;
          if (cancelled) return;
          panelState.setHasWarmCachePreview(false);
          panelState.setError(state.error);
          panelState.setIsOfflineCached(state.loadedFromOfflineCache);
          panelState.setIsLoading(false);
          return;
        } catch (retryError) {
          const retryMessage =
            retryError instanceof Error ? retryError.message : "Failed to load document";
          panelState.setError(retryMessage);
          state.error = retryMessage;
          panelState.setIsLoading(false);
          return;
        }
      }
      if (state && isAccessDenied && state.access.kind === "share") {
        requestShareReentry(stateKey);
        panelState.setHasWarmCachePreview(false);
        panelState.setIsOfflineCached(false);
        panelState.setIsAccessRevoked(false);
        panelState.setError(null);
        panelState.setIsLoading(false);
        return;
      }
      if (state && !state.initialized && !isSecurityFailure && !isDeleted) {
        try {
          const recovered = await initializeDocumentFromCache(documentId, workspaceId, state);
          if (recovered && !cancelled) {
            if (isAccessDenied) {
              if (state.autoSync) {
                state.autoSync.dispose();
                state.autoSync = null;
              }
              state.readOnly = true;
              panelState.setHasWarmCachePreview(false);
              panelState.setIsOfflineCached(true);
              panelState.setIsAccessRevoked(true);
              panelState.setError(null);
              panelState.setIsLoading(false);
              return;
            }
            panelState.setHasWarmCachePreview(false);
            panelState.setIsOfflineCached(true);
            panelState.setError(null);
            panelState.setIsLoading(false);
            return;
          }
        } catch {
          // Recovery failed, fall through to error
        }
      }
      if (state && isServerUnreachable && !state.initialized && !isSecurityFailure && !isDeleted) {
        scheduleInitialRetry(state);
        return;
      }
      const message = err instanceof Error ? err.message : "Failed to load document";
      panelState.setError(message);
      if (state) state.error = message;
    } finally {
      if (!cancelled) panelState.setIsLoading(false);
    }
  })();
  return () => {
    cancelled = true;
    if (retryTimer) clearTimeout(retryTimer);
    releaseDocumentState(stateKey);
  };
}
