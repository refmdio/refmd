import { acquireDocumentState, getDocumentState } from "../../../model/document-state/store";
import { releaseDocumentState } from "../../../model/document-state/lifecycle";
import { requestReauth } from "../../../model/document-state/signals";
import { initializeDocumentSync } from "../initialize";
import { DocumentChannelError, DocumentSyncError } from "../error";
import { initializeDocumentFromCache, restoreDocumentStateFromCache } from "../../offline/restore";
interface DocumentPanelLifecycleState {
  setError: (value: string | null) => void;
  setHasWarmCachePreview: (value: boolean) => void;
  setIsAccessRevoked: (value: boolean) => void;
  setIsDocumentDeleted: (value: boolean) => void;
  setIsLoading: (value: boolean) => void;
  setIsOfflineCached: (value: boolean) => void;
}
function hasWarmCacheState(documentId: string): boolean {
  const state = getDocumentState(documentId);
  if (!state) return false;
  return (
    state.keyVersion > 0 ||
    state.activeSnapshotId !== null ||
    state._cachedConfirmedStateVector !== null ||
    state.loadedFromOfflineCache
  );
}
export function initializeDocumentPanel(
  documentId: string,
  workspaceId: string | null,
  panelState: DocumentPanelLifecycleState,
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
  void (async () => {
    try {
      await acquireDocumentState(documentId, workspaceId);
      const state = getDocumentState(documentId);
      if (!state || cancelled) return;
      if (!state.initialized && !hasWarmCacheState(documentId)) {
        try {
          const recovered = await restoreDocumentStateFromCache(documentId, workspaceId, state);
          if (recovered && !cancelled) {
            panelState.setHasWarmCachePreview(true);
            panelState.setIsLoading(false);
          }
        } catch {
          // Best-effort: warm preview is opportunistic
        }
      } else if (!state.initialized && hasWarmCacheState(documentId)) {
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
      const isSecurityFailure =
        err instanceof DocumentSyncError &&
        (err.code === "rollback_attack" || err.code === "verification_failed");
      const isAuthFailure = err instanceof DocumentSyncError && err.code === "unauthorized";
      const isAccessDenied =
        err instanceof DocumentChannelError &&
        (err.code === "not_a_member" || err.code === "permission_denied");
      const isDeleted = err instanceof DocumentChannelError && err.code === "document_not_found";
      const state = getDocumentState(documentId);
      panelState.setIsDocumentDeleted(isDeleted);
      if (state && isAuthFailure) {
        try {
          await requestReauth(documentId);
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
      const message = err instanceof Error ? err.message : "Failed to load document";
      panelState.setError(message);
      if (state) state.error = message;
    } finally {
      if (!cancelled) panelState.setIsLoading(false);
    }
  })();
  return () => {
    cancelled = true;
    releaseDocumentState(documentId);
  };
}
