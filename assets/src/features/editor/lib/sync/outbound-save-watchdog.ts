import type { DocumentState } from "../../model/document-state/types";

const SAVE_ACK_TIMEOUT_MS = 15_000;

export function clearSaveAckWatchdog(state: DocumentState): void {
  if (state.pendingSaveTimeout) {
    clearTimeout(state.pendingSaveTimeout);
    state.pendingSaveTimeout = null;
  }
}

export function armSaveAckWatchdog(
  state: DocumentState,
  onTimeout: (kind: "update" | "snapshot") => void,
  kind: "update" | "snapshot",
): void {
  clearSaveAckWatchdog(state);
  state.pendingSaveTimeout = setTimeout(() => {
    state.pendingSaveTimeout = null;
    if (!state.sending) return;
    state.sending = false;
    onTimeout(kind);
  }, SAVE_ACK_TIMEOUT_MS);
}
