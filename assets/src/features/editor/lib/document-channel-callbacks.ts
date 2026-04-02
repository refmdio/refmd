import type { DocumentChannelCallbacks } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentState } from "./document-state-cache";
import { handleEphemeralMessage, handlePeerLeft } from "./ws-ephemeral-handler";
import { handleRemoteSnapshot, handleRemoteUpdate } from "./ws-handlers";
import {
  handleSnapshotSaveFailed,
  handleSnapshotSaved,
  handleUpdateSaveFailed,
  handleUpdateSaved,
} from "./ws-handlers-save";

interface DocumentChannelLifecycleHandlers {
  onDocument: DocumentChannelCallbacks["onDocument"];
  onUnauthorized: DocumentChannelCallbacks["onUnauthorized"];
  onError: DocumentChannelCallbacks["onError"];
  onClose: DocumentChannelCallbacks["onClose"];
}

export function buildDocumentChannelCallbacks(
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
  handlers: DocumentChannelLifecycleHandlers,
): DocumentChannelCallbacks {
  return {
    onDocument: handlers.onDocument,
    onUpdate: (payload) => {
      handleRemoteUpdate(payload, state, documentId, localDeviceSigningPubKey).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onSnapshot: (payload) => {
      handleRemoteSnapshot(payload, state, documentId).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onUpdateSaved: (payload) => {
      handleUpdateSaved(payload, state, documentId);
    },
    onUpdateSaveFailed: (payload) => {
      handleUpdateSaveFailed(payload, state);
      if (payload.requiresNewSnapshot) {
        failClosed("snapshot_mismatch");
      }
    },
    onSnapshotSaved: (payload) => {
      handleSnapshotSaved(payload, state, documentId);
    },
    onSnapshotSaveFailed: (payload) => {
      handleSnapshotSaveFailed(payload, state, documentId).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onEphemeralMessage: (payload) => {
      handleEphemeralMessage(payload, state, documentId, localDeviceSigningPubKey, failClosed);
    },
    onPeerLeft: (payload) => {
      handlePeerLeft(payload, state);
    },
    onUnauthorized: handlers.onUnauthorized,
    onError: handlers.onError,
    onClose: handlers.onClose,
  };
}
