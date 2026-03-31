import { getAllActiveDocumentStates } from "./document-state-cache";
import { cacheDocumentState, cachePendingChanges } from "@/shared/lib/offline/cache-manager";
import { onOfflineModeChange } from "@/shared/lib/offline/offline-state";

function flushAllActive(): void {
  const states = getAllActiveDocumentStates();
  for (const [documentId, state] of states) {
    if (state.initialized && state.keyVersion > 0) {
      cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
      cachePendingChanges(documentId, state).catch(() => {});
    }
  }
}

export function setupFlushHooks(): () => void {
  const handleVisibilityChange = () => {
    if (document.visibilityState === "hidden") {
      flushAllActive();
    }
  };

  const handleBeforeUnload = () => {
    flushAllActive();
  };

  // Immediate flush when transitioning to offline mode
  const cleanupOfflineListener = onOfflineModeChange((isOffline) => {
    if (isOffline) {
      flushAllActive();
    }
  });

  document.addEventListener("visibilitychange", handleVisibilityChange);
  window.addEventListener("beforeunload", handleBeforeUnload);

  return () => {
    document.removeEventListener("visibilitychange", handleVisibilityChange);
    window.removeEventListener("beforeunload", handleBeforeUnload);
    cleanupOfflineListener();
  };
}
