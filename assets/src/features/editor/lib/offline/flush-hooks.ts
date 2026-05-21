import { getAllActiveDocumentStates } from "../../model/document-state/store";
import type { DocumentState } from "../../model/document-state/types";
import { flushDocumentCache } from "@/shared/lib/offline/cache/manager/write";
import { onOfflineModeChange } from "@/shared/lib/offline/offline-state";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";

const LOGOUT_SAVE_WAIT_MS = 12_000;
const SAVE_IDLE_POLL_MS = 100;

function flushAllActive(): void {
  const states = getAllActiveDocumentStates();
  for (const [documentId, state] of states) {
    flushDocumentCache(documentId, state.workspaceId, state);
  }
}

function isSaveIdle(state: DocumentState): boolean {
  return (
    !state.sending &&
    !state.pendingUpdateEnvelope &&
    !state.pendingSnapshot &&
    !state.pendingSnapshotEnvelope
  );
}

function waitForSaveIdle(state: DocumentState): Promise<void> {
  if (isSaveIdle(state)) return Promise.resolve();

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const poll = () => {
      if (isSaveIdle(state) || Date.now() - startedAt >= LOGOUT_SAVE_WAIT_MS) {
        resolve();
        return;
      }
      setTimeout(poll, SAVE_IDLE_POLL_MS);
    };
    poll();
  });
}

async function flushAllActiveBeforeSessionCleanup(): Promise<void> {
  const states = [...getAllActiveDocumentStates()];
  await Promise.allSettled(
    states.map(async ([documentId, state]) => {
      if (state.access.kind !== "share") {
        flushDocumentCache(documentId, state.workspaceId, state);
      }
      await state.autoSync?.flushNow();
      await waitForSaveIdle(state);
    }),
  );
}

export function setupFlushHooks(): () => void {
  const unregisterBeforeSessionCleanup = registerBeforeSessionCleanup(
    flushAllActiveBeforeSessionCleanup,
  );

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
    unregisterBeforeSessionCleanup();
  };
}
