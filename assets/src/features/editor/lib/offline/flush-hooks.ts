import { getAllActiveDocumentStates } from "../../model/document-state/store";
import { flushDocumentCache } from "@/shared/lib/offline/cache/manager/write";
import { onOfflineModeChange } from "@/shared/lib/offline/offline-state";

function flushAllActive(): void {
  const states = getAllActiveDocumentStates();
  for (const [documentId, state] of states) {
    flushDocumentCache(documentId, state.workspaceId, state);
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
