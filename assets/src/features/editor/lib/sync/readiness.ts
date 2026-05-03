import { getChannelState } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentState } from "../../model/document-state/types";

export function canBufferDisconnectedChanges(state: DocumentState | undefined): boolean {
  if (!state) return false;
  return (
    state.initialized &&
    state.keyVersion > 0 &&
    !!state.activeSnapshotId &&
    !!state.snapshotProofHash &&
    !!state.snapshotCiphertextHash &&
    !!state.lastSavedState &&
    !state.error &&
    !state.sending &&
    !state.pendingUpdateEnvelope &&
    !state.pendingSnapshotEnvelope
  );
}

export function isDocumentSyncReady(state: DocumentState | undefined): boolean {
  if (!state || !state.initialized || state._reconnecting || state._syncPaused) return false;
  return !!state.channel && getChannelState(state.channel) === "joined";
}
