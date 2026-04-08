import { getPopHeaders } from "@/shared/lib/auth/pop";
import {
  rejoinDocument,
  isPhoenixJoinError,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/phoenix-channel";
import { requestReauth } from "../../../model/document-state/signals";
import { getDocumentState } from "../../../model/document-state/store";
import type { DocumentState } from "../../../model/document-state/types";
import { buildDocumentChannelCallbacks } from "../bootstrap/callbacks";
import { resumeReconnectDocument } from "./resume";

const MAX_RECONNECT_ATTEMPTS = 13;
const RECONNECT_BASE_MS = 100;
const RECONNECT_MAX_MS = 30_000;

export function triggerReconnect(
  state: DocumentState,
  documentId: string,
  workspaceId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): void {
  if (!getDocumentState(documentId)) return;
  if (state.error) return;
  if (state._reconnecting) return;

  state.channel = null;
  state.sending = false;
  state.awarenessRelayCleanup?.();
  state.awarenessRelayCleanup = null;
  state.ephemeralSession = null;
  state._reconnecting = true;

  attemptReconnect(documentId, workspaceId, state, localDeviceSigningPubKey, failClosed).finally(
    () => {
      state._reconnecting = false;
      if (!state.error && !state.channel && getDocumentState(documentId)) {
        triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
      }
    },
  );
}

async function attemptReconnect(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  let useDelta = !!state.activeSnapshotId;

  for (let attempt = 0; attempt < MAX_RECONNECT_ATTEMPTS; attempt++) {
    if (state.error || !getDocumentState(documentId)) return;

    const delay = Math.min(RECONNECT_BASE_MS * Math.pow(1.8, attempt), RECONNECT_MAX_MS);
    await new Promise((r) => setTimeout(r, delay));

    if (state.error || !getDocumentState(documentId)) return;

    try {
      const popHeaders = await getPopHeaders();
      const joinParams: Record<string, unknown> = {
        pop_challenge: popHeaders["X-PoP-Challenge"],
        pop_signature: popHeaders["X-PoP-Signature"],
        mode: useDelta ? "delta" : "complete",
      };
      state._lastJoinMode = useDelta ? "delta" : "complete";
      if (state.activeSnapshotId) {
        joinParams.knownSnapshotId = state.activeSnapshotId;
      }
      if (useDelta && state.activeSnapshotId) {
        joinParams.knownSnapshotUpdateClocks = { ...state.confirmedClocks };
      }

      let documentHandled: Promise<void> | null = null;
      let earlyCloseReject: ((err: Error) => void) | null = null;

      const callbacks = buildDocumentChannelCallbacks(
        state,
        documentId,
        localDeviceSigningPubKey,
        failClosed,
        {
          onDocument: (payload) => {
            documentHandled = resumeReconnectDocument(
              payload,
              state,
              documentId,
              localDeviceSigningPubKey,
              failClosed,
            );
          },
          onUnauthorized: () => {
            // Session expired mid-connection: trigger reconnect which handles re-auth
            triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
          },
          onUpdateSaveFailed: (payload) => {
            if (!payload.requiresNewSnapshot) {
              triggerReconnect(
                state,
                documentId,
                workspaceId,
                localDeviceSigningPubKey,
                failClosed,
              );
            }
          },
          onError: (reason) => {
            if (
              reason === "document_not_found" ||
              reason === "document_error" ||
              reason === "connection_cap_evict"
            ) {
              failClosed(String(reason));
            } else {
              triggerReconnect(
                state,
                documentId,
                workspaceId,
                localDeviceSigningPubKey,
                failClosed,
              );
            }
          },
          onClose: () => {
            if (earlyCloseReject) {
              earlyCloseReject(
                new PhoenixChannelTransportError(
                  "disconnected_before_document",
                  "Disconnected before document received",
                ),
              );
            } else {
              triggerReconnect(
                state,
                documentId,
                workspaceId,
                localDeviceSigningPubKey,
                failClosed,
              );
            }
          },
        },
      );

      state.channel = null;
      state.initialized = false;
      state._pendingRemoteEvents = [];
      const channel = await rejoinDocument(documentId, joinParams, callbacks);
      state.channel = channel;

      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          clearTimeout(timer);
          clearInterval(check);
          earlyCloseReject = null;
        };
        earlyCloseReject = (err: Error) => {
          cleanup();
          reject(err);
        };
        const timer = setTimeout(() => {
          if (!documentHandled) {
            cleanup();
            reject(new Error("Reconnect document message timeout"));
          }
        }, 30_000);
        const check = setInterval(() => {
          if (documentHandled) {
            cleanup();
            documentHandled.then(resolve, reject);
          }
        }, 100);
      });
      return;
    } catch (err) {
      const resp = isPhoenixJoinError(err) ? err.joinErrorResp : undefined;
      const reason = resp?.reason;
      if (reason === "not_a_member" || reason === "permission_denied") {
        // Access revoked: switch to read-only cached mode, purge KEK
        state.readOnly = true;
        if (state.autoSync) {
          state.autoSync.dispose();
          state.autoSync = null;
        }
        import("@/shared/lib/offline/storage/store").then(({ deleteOfflineKek }) =>
          deleteOfflineKek(workspaceId).catch(() => {}),
        );
        import("@/shared/lib/notice")
          .then(({ Notice }) => new Notice("Workspace access revoked. Document is now read-only."))
          .catch(() => {});
        return;
      }
      if (reason === "document_not_found" || reason === "pop_verification_failed") {
        failClosed(reason);
        return;
      }
      if (reason === "unauthorized") {
        // Session expired: request re-authentication and retry
        await requestReauth(documentId);
        // After re-auth completes, reset attempt counter and retry
        attempt = -1; // Will be incremented to 0 by the loop
        useDelta = !!state.activeSnapshotId;
        continue;
      }
      if (useDelta) useDelta = false;
    }
  }

  failClosed("reconnect_exhausted");
}
