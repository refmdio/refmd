import { getPopHeaders } from "@/shared/lib/auth/pop";
import { getRateLimitRetryMs } from "@/shared/api/core";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";
import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  hasCompleteSnapshotPin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import {
  getChannelState,
  leaveDocument,
  rejoinDocument,
  isPhoenixJoinError,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/phoenix-channel";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { isRecoverableSyncGapError } from "../error";
import {
  needsShareReentry,
  requestReauth,
  requestShareReentry,
  setDocumentSyncPaused,
} from "../../../model/document-state/signals";
import { getDocumentState } from "../../../model/document-state/store";
import type { DocumentState } from "../../../model/document-state/types";
import { isRawSharedDocumentAccess } from "../../../model/document-state/access";
import { buildDocumentChannelCallbacks } from "../bootstrap/callbacks";
import { resumeReconnectDocument } from "./resume";

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_BASE_MS = 100;
const RECONNECT_MAX_MS = 5_000;
const RECONNECT_DOCUMENT_TIMEOUT_MS = 8_000;

function getStateKnownSnapshotId(state: DocumentState): string | null {
  return state.activeSnapshotId && state.snapshotProofHash && state.snapshotCiphertextHash
    ? state.activeSnapshotId
    : null;
}

function getPinKey(documentId: string, state: DocumentState): string {
  return state.access.kind === "share"
    ? buildDocumentStatePinKey(documentId, state.access.shareId)
    : buildDocumentStatePinKey(documentId);
}

function isTransientReconnectError(error: unknown): boolean {
  return (
    error instanceof TypeError ||
    error instanceof PhoenixChannelTransportError ||
    getRateLimitRetryMs(error) !== null
  );
}

export function triggerReconnect(
  state: DocumentState,
  documentId: string,
  workspaceId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): void {
  if (!getDocumentState(state.stateKey)) return;
  if (state.error) return;
  if (state._reconnecting) return;
  if (state._reconnectTimer) return;
  if (needsShareReentry(state.stateKey)) return;

  state.channel = null;
  state.sending = false;
  state.awarenessRelayCleanup?.();
  state.awarenessRelayCleanup = null;
  state.ephemeralSession = null;
  state._reconnecting = true;
  setDocumentSyncPaused(state.stateKey, true);

  attemptReconnect(documentId, workspaceId, state, localDeviceSigningPubKey, failClosed).finally(
    () => {
      state._reconnecting = false;
      if (!state.error && state.initialized && state.channel) {
        setDocumentSyncPaused(state.stateKey, false);
      }
      if (
        !state.error &&
        !state.channel &&
        !needsShareReentry(state.stateKey) &&
        getDocumentState(state.stateKey)
      ) {
        scheduleReconnectAttempt(
          state,
          documentId,
          workspaceId,
          localDeviceSigningPubKey,
          failClosed,
        );
      }
    },
  );
}

function scheduleReconnectAttempt(
  state: DocumentState,
  documentId: string,
  workspaceId: string,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): void {
  if (state._reconnectTimer || state._reconnecting || state.error) return;
  const delay = Math.max(getAuthTransportBackoffMs(), RECONNECT_MAX_MS);
  setDocumentSyncPaused(state.stateKey, true);
  state._reconnectTimer = setTimeout(() => {
    state._reconnectTimer = null;
    triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
  }, delay);
}

async function attemptReconnect(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  localDeviceSigningPubKey: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  let useDelta = !!getStateKnownSnapshotId(state) && !state._forceCompleteReconnect;
  state._forceCompleteReconnect = false;
  let lastError: unknown = null;
  let sawNonTransientError = false;

  for (let attempt = 0; attempt < MAX_RECONNECT_ATTEMPTS; attempt++) {
    if (state.error || !getDocumentState(state.stateKey)) return;

    const delay =
      attempt === 0 ? 0 : Math.min(RECONNECT_BASE_MS * Math.pow(1.8, attempt), RECONNECT_MAX_MS);
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));

    if (state.error || !getDocumentState(state.stateKey)) return;

    let unauthorizedDuringReconnect = false;
    try {
      // Ensure socket auth exists before consuming a single-use PoP challenge.
      await ensurePhoenixWsToken(isRawSharedDocumentAccess(state.access) ? "share" : "user");
      const popHeaders = isRawSharedDocumentAccess(state.access)
        ? await getPopHeaders(
            state.access.participantDeviceId,
            undefined,
            "share",
            getShareParticipantCryptoWorker(state.access.shareSlug),
          )
        : await getPopHeaders(undefined, undefined, "user");
      const stateKnownSnapshotId = getStateKnownSnapshotId(state);
      const pin = await getDocumentStatePin(getPinKey(documentId, state)).catch(() => null);
      const pinSnapshotId = hasCompleteSnapshotPin(pin) ? pin.latestSnapshotId : null;
      useDelta =
        useDelta &&
        !!stateKnownSnapshotId &&
        (!pinSnapshotId || pinSnapshotId === stateKnownSnapshotId);
      const knownSnapshotId = useDelta
        ? stateKnownSnapshotId
        : (pinSnapshotId ?? stateKnownSnapshotId);
      const joinParams: Record<string, unknown> = {
        pop_challenge: popHeaders["X-PoP-Challenge"],
        pop_signature: popHeaders["X-PoP-Signature"],
        mode: useDelta ? "delta" : "complete",
      };
      state._lastJoinMode = useDelta ? "delta" : "complete";
      if (knownSnapshotId) {
        joinParams.knownSnapshotId = knownSnapshotId;
      }
      if (state.access.kind === "share" && state.access.mountId) {
        joinParams.mount_id = state.access.mountId;
      }
      if (useDelta && stateKnownSnapshotId) {
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
            if (documentHandled) return;
            documentHandled = resumeReconnectDocument(
              payload,
              state,
              documentId,
              localDeviceSigningPubKey,
              failClosed,
            );
          },
          onUnauthorized: () => {
            unauthorizedDuringReconnect = true;
            earlyCloseReject?.(
              new PhoenixChannelTransportError(
                "disconnected_before_document",
                "Unauthorized during reconnect",
              ),
            );
          },
          onUpdateSaveFailed: (payload) => {
            if (!payload.requiresNewSnapshot) {
              state._forceCompleteReconnect = true;
              triggerReconnect(
                state,
                documentId,
                workspaceId,
                localDeviceSigningPubKey,
                failClosed,
              );
            }
          },
          onSyncGap: (err) => {
            void err;
            state._forceCompleteReconnect = true;
            triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
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
      state._pendingOutOfOrderUpdates = [];
      if (state._syncGapTimer) {
        clearTimeout(state._syncGapTimer);
        state._syncGapTimer = null;
      }
      const channel = await rejoinDocument(documentId, joinParams, callbacks, state.stateKey);
      state.channel = channel;

      await new Promise<void>((resolve, reject) => {
        let attached = false;
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
            return;
          }
          if (state.initialized && state.channel && getChannelState(state.channel) === "joined") {
            cleanup();
            resolve();
            return;
          }
          cleanup();
          reject(new Error("Reconnect document handling timeout"));
        }, RECONNECT_DOCUMENT_TIMEOUT_MS);
        const check = setInterval(() => {
          if (documentHandled && !attached) {
            attached = true;
            clearInterval(check);
            documentHandled.then(
              () => {
                cleanup();
                resolve();
              },
              (err) => {
                cleanup();
                reject(err);
              },
            );
          }
        }, 100);
      });
      return;
    } catch (err) {
      lastError = err;
      if (state.channel) {
        leaveDocument(documentId, state.stateKey);
        state.channel = null;
      }
      if (unauthorizedDuringReconnect) {
        if (state.access.kind === "share") {
          requestShareReentry(state.stateKey);
          return;
        }
        await requestReauth(state.stateKey);
        attempt = -1;
        useDelta = false;
        continue;
      }
      if (isRecoverableSyncGapError(err)) {
        useDelta = false;
        continue;
      }
      const resp = isPhoenixJoinError(err) ? err.joinErrorResp : undefined;
      const reason = resp?.reason;
      if (reason === "not_a_member" || reason === "permission_denied") {
        if (state.access.kind === "share") {
          requestShareReentry(state.stateKey);
          return;
        }

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
        if (state.access.kind === "share") {
          requestShareReentry(state.stateKey);
          return;
        }

        // Session expired: request re-authentication and retry
        await requestReauth(state.stateKey);
        // After re-auth completes, reset attempt counter and retry
        attempt = -1; // Will be incremented to 0 by the loop
        useDelta = !!getStateKnownSnapshotId(state);
        continue;
      }
      if (isTransientReconnectError(err)) {
        continue;
      }
      sawNonTransientError = true;
      if (useDelta) {
        useDelta = false;
        continue;
      }
      failClosed("reconnect_failed", err);
      return;
    }
  }

  if (sawNonTransientError) {
    failClosed("reconnect_failed", lastError);
    return;
  }

  await new Promise((resolve) => setTimeout(resolve, RECONNECT_MAX_MS));
}
