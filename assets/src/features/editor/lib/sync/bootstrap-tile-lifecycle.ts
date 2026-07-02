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

const tileInitializationLocks = new Map<string, Promise<void>>();

interface DocumentTileLifecycleState {
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
function hasShareBootstrapInitialDocument(
  state: NonNullable<ReturnType<typeof getDocumentState>>,
): boolean {
  return state.access.kind === "share" && Boolean(state.access.initialDocument);
}
function isCancelledInitializationError(error: unknown): boolean {
  if (isInitCancelledError(error)) return true;
  return error instanceof Error && error.message.toLowerCase().includes("aborted");
}

function revealInitializedDocument(
  state: NonNullable<ReturnType<typeof getDocumentState>>,
  tileState: DocumentTileLifecycleState,
): void {
  tileState.setHasWarmCachePreview(false);
  tileState.setIsOfflineCached(state.loadedFromOfflineCache);
  tileState.setError(state.error);
  tileState.setIsLoading(false);
}

function watchInitializedDocument(
  state: NonNullable<ReturnType<typeof getDocumentState>>,
  tileState: DocumentTileLifecycleState,
  isCancelled: () => boolean,
): () => void {
  if (state.initialized && !isCancelled()) {
    revealInitializedDocument(state, tileState);
    return () => {};
  }

  const timer = setInterval(() => {
    if (isCancelled()) {
      clearInterval(timer);
      return;
    }
    if (!state.initialized) return;
    clearInterval(timer);
    revealInitializedDocument(state, tileState);
  }, 25);

  return () => clearInterval(timer);
}

export function initializeDocumentTile(
  documentId: string,
  workspaceId: string | null,
  tileState: DocumentTileLifecycleState,
  stateKey = documentId,
): () => void {
  if (!workspaceId) {
    tileState.setError("No workspace selected");
    tileState.setIsLoading(false);
    return () => {};
  }
  const existingState = getDocumentState(stateKey);
  const hasWarmState = hasWarmCacheState(stateKey);
  const alreadyReady = existingState?.initialized && !existingState.error;
  tileState.setIsLoading(!alreadyReady && !hasWarmState);
  tileState.setError(null);
  tileState.setIsOfflineCached(existingState?.loadedFromOfflineCache ?? false);
  tileState.setIsAccessRevoked(false);
  tileState.setIsDocumentDeleted(false);
  tileState.setHasWarmCachePreview(!alreadyReady && hasWarmState);
  let cancelled = false;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  const scheduleInitialRetry = (state: NonNullable<ReturnType<typeof getDocumentState>>) => {
    if (retryTimer || state.initialized) return;
    const delay = Math.max(getAuthTransportBackoffMs(), 1_000);
    state.error = null;
    tileState.setError(null);
    tileState.setIsLoading(false);
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (cancelled || state.initialized || state.initPromise) return;
      tileState.setIsLoading(true);
      state.error = null;
      const retryInitPromise = initializeDocumentSync(documentId, workspaceId, state);
      state.initPromise = retryInitPromise;
      retryInitPromise
        .then(() => {
          if (cancelled) return;
          tileState.setHasWarmCachePreview(false);
          tileState.setError(state.error);
          tileState.setIsOfflineCached(state.loadedFromOfflineCache);
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
          tileState.setError(retryMessage);
        })
        .finally(() => {
          if (state.initPromise === retryInitPromise && !state.initialized) {
            state.initPromise = null;
          }
          if (!cancelled) tileState.setIsLoading(false);
        });
    }, delay);
  };
  void (async () => {
    try {
      await acquireDocumentState(documentId, workspaceId, stateKey);
      const state = getDocumentState(stateKey);
      if (!state || cancelled) return;

      if (
        !state.initialized &&
        !hasShareBootstrapInitialDocument(state) &&
        shouldPreferOfflineCache()
      ) {
        const recovered = await initializeDocumentFromCache(documentId, workspaceId, state);
        if (recovered && !cancelled) {
          tileState.setHasWarmCachePreview(false);
          tileState.setIsOfflineCached(true);
          tileState.setError(null);
          tileState.setIsLoading(false);
          return;
        }
      }

      if (!state.initialized && !state.initPromise) {
        let initializationLock = tileInitializationLocks.get(stateKey);
        if (!initializationLock) {
          initializationLock = (async () => {
            if (
              !state.initialized &&
              !hasWarmCacheState(stateKey) &&
              !hasShareBootstrapInitialDocument(state)
            ) {
              try {
                const recovered = await restoreDocumentStateFromCache(
                  documentId,
                  workspaceId,
                  state,
                );
                if (recovered && !cancelled) {
                  tileState.setHasWarmCachePreview(true);
                  tileState.setIsLoading(false);
                }
              } catch {
                // Best-effort: warm preview is opportunistic
              }
            } else if (!state.initialized && hasWarmCacheState(stateKey) && !cancelled) {
              tileState.setHasWarmCachePreview(true);
              tileState.setIsLoading(false);
            }
            if (!state.initialized && !state.initPromise) {
              state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
            }
          })().finally(() => {
            if (tileInitializationLocks.get(stateKey) === initializationLock) {
              tileInitializationLocks.delete(stateKey);
            }
          });
          tileInitializationLocks.set(stateKey, initializationLock);
        }
        await initializationLock;
      } else if (!state.initialized && hasWarmCacheState(stateKey)) {
        tileState.setHasWarmCachePreview(true);
        tileState.setIsLoading(false);
      }
      if (!state.initialized && !state.initPromise) {
        state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
      }
      if (state.initPromise) {
        const stopInitializedWatch = watchInitializedDocument(state, tileState, () => cancelled);
        try {
          await state.initPromise;
        } finally {
          stopInitializedWatch();
        }
      }
      if (cancelled) return;
      tileState.setHasWarmCachePreview(false);
      if (state.error) {
        tileState.setError(state.error);
      }
      if (state.loadedFromOfflineCache) {
        tileState.setIsOfflineCached(true);
      }
    } catch (err) {
      if (cancelled) return;
      const state = getDocumentState(stateKey);
      if (state && isCancelledInitializationError(err)) {
        if (state.initialized) {
          setDocumentError(stateKey, null);
          tileState.setError(null);
          tileState.setHasWarmCachePreview(false);
          tileState.setIsOfflineCached(state.loadedFromOfflineCache);
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
      tileState.setIsDocumentDeleted(isDeleted);
      if (state && isAuthFailure) {
        if (state.access.kind === "share") {
          requestShareReentry(stateKey);
          tileState.setIsLoading(false);
          return;
        }

        try {
          await requestReauth(stateKey);
          if (cancelled) return;
          state.error = null;
          state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
          await state.initPromise;
          if (cancelled) return;
          tileState.setHasWarmCachePreview(false);
          tileState.setError(state.error);
          tileState.setIsOfflineCached(state.loadedFromOfflineCache);
          tileState.setIsLoading(false);
          return;
        } catch (retryError) {
          const retryMessage =
            retryError instanceof Error ? retryError.message : "Failed to load document";
          tileState.setError(retryMessage);
          state.error = retryMessage;
          tileState.setIsLoading(false);
          return;
        }
      }
      if (state && isAccessDenied && state.access.kind === "share") {
        requestShareReentry(stateKey);
        tileState.setHasWarmCachePreview(false);
        tileState.setIsOfflineCached(false);
        tileState.setIsAccessRevoked(false);
        tileState.setError(null);
        tileState.setIsLoading(false);
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
              tileState.setHasWarmCachePreview(false);
              tileState.setIsOfflineCached(true);
              tileState.setIsAccessRevoked(true);
              tileState.setError(null);
              tileState.setIsLoading(false);
              return;
            }
            tileState.setHasWarmCachePreview(false);
            tileState.setIsOfflineCached(true);
            tileState.setError(null);
            tileState.setIsLoading(false);
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
      tileState.setError(message);
      if (state) state.error = message;
    } finally {
      if (!cancelled) tileState.setIsLoading(false);
    }
  })();
  return () => {
    cancelled = true;
    if (retryTimer) clearTimeout(retryTimer);
    releaseDocumentState(stateKey);
  };
}
