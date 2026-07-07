import { buildChannelPopResource, getChannelPopParams } from "@/shared/lib/auth/pop";
import { deviceState } from "@/entities/session";
import { getRateLimitRetryMs } from "@/shared/api/core";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";
import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  hasCompleteSnapshotPin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  getChannelState,
  getPhoenixJoinErrorReason,
  leaveDocument,
  rejoinDocument,
  isPhoenixJoinError,
  PhoenixChannelTransportError,
  resetPhoenixConnection,
} from "@/shared/lib/ws/phoenix-channel";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { isRecoverableSyncGapError } from "./error";
import {
  needsShareReentry,
  requestReauth,
  requestShareReentry,
  setDocumentSyncPaused,
} from "../../model/document-state/signals";
import { getDocumentState } from "../../model/document-state/store";
import type { DocumentState } from "../../model/document-state/types";
import { buildDocumentChannelCallbacks } from "./bootstrap-callbacks";
import { refreshWorkspaceKeyDirectoryForDocumentJoin } from "./bootstrap-prepare";
import { shouldUseDeltaReconnect } from "./reconnect-decisions";
import { resumeReconnectDocument } from "./reconnect-resume";
import { refreshSharedDocumentAccess } from "./share-access";
import { recordSyncPerf } from "./perf";

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_BASE_MS = 100;
const RECONNECT_MAX_MS = 5_000;
const RECONNECT_DOCUMENT_TIMEOUT_MS = 8_000;
const WORKSPACE_KEY_DIRECTORY_REFRESH_REQUIRED = "workspace_key_directory_refresh_required";

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

function recordJoinDecision(
  state: DocumentState,
  knownSnapshotId: string | null,
  pinSnapshotId: string | null,
  stateSnapshotId: string | null,
  useDelta: boolean,
): void {
  state._lastJoinDecision = {
    hasLastSavedState: state.lastSavedState !== null,
    hasSnapshotCiphertextHash: state.snapshotCiphertextHash.length > 0,
    hasSnapshotProofHash: state.snapshotProofHash.length > 0,
    knownSnapshotId,
    pinSnapshotId,
    stateSnapshotId,
    useDelta,
  };
}

function isTransientReconnectError(error: unknown): boolean {
  return (
    error instanceof TypeError ||
    error instanceof PhoenixChannelTransportError ||
    getRateLimitRetryMs(error) !== null
  );
}

function isWorkspaceKeyDirectoryRefreshRequired(error: unknown): boolean {
  return getPhoenixJoinErrorReason(error) === WORKSPACE_KEY_DIRECTORY_REFRESH_REQUIRED;
}

export function triggerReconnect(
  state: DocumentState,
  documentId: string,
  workspaceId: string,
  localDeviceSigningKeyId: string | undefined,
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

  void attemptReconnect(
    documentId,
    workspaceId,
    state,
    localDeviceSigningKeyId,
    failClosed,
  ).finally(() => {
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
      scheduleReconnectAttempt(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
    }
  });
}

function scheduleReconnectAttempt(
  state: DocumentState,
  documentId: string,
  workspaceId: string,
  localDeviceSigningKeyId: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): void {
  if (state._reconnectTimer || state._reconnecting || state.error) return;
  const delay = Math.max(getAuthTransportBackoffMs(), RECONNECT_MAX_MS);
  setDocumentSyncPaused(state.stateKey, true);
  state._reconnectTimer = setTimeout(() => {
    state._reconnectTimer = null;
    triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
  }, delay);
}

async function attemptReconnect(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  localDeviceSigningKeyId: string | undefined,
  failClosed: (reason: string, err?: unknown) => void,
): Promise<void> {
  let useDelta = shouldUseDeltaReconnect({
    stateKnownSnapshotId: getStateKnownSnapshotId(state),
    pinSnapshotId: null,
    hasLastSavedState: state.lastSavedState !== null,
    forceCompleteReconnect: state._forceCompleteReconnect,
  });
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
      const transportScope = state.access.kind === "share" ? "share" : "user";
      await ensurePhoenixWsToken(transportScope);
      const stateKnownSnapshotId = getStateKnownSnapshotId(state);
      const pin = await getDocumentStatePin(getPinKey(documentId, state)).catch(() => null);
      const mountedShareReconnect =
        state.access.kind === "share" &&
        state.access.source === "mounted" &&
        !!state.access.mountId;
      if (mountedShareReconnect) {
        const access = await refreshSharedDocumentAccess(state);
        await access.workspacePinReady;
      }
      let workspacePin = await getKeyDirectoryPin("workspace", state.workspaceId).catch(() => null);
      if (!workspacePin) {
        if (state.access.kind === "share") {
          const access = mountedShareReconnect
            ? state.access
            : await refreshSharedDocumentAccess(state);
          await access.workspacePinReady;
          workspacePin = await getKeyDirectoryPin("workspace", state.workspaceId).catch(() => null);
          if (!workspacePin) {
            await fetchVerifiedKeyDirectory({
              scopeKind: "workspace",
              scopeId: state.workspaceId,
              popDeviceId: state.access.participantDeviceId,
              popScope: "share",
              popWorker: getShareParticipantCryptoWorker(state.access.shareSlug),
            });
          }
        } else {
          const device = deviceState();
          if (!device?.deviceId) throw new Error("key_directory_pop_device_required");
          await fetchVerifiedKeyDirectory({
            scopeKind: "workspace",
            scopeId: state.workspaceId,
            popDeviceId: device.deviceId,
          });
        }
        workspacePin = await getKeyDirectoryPin("workspace", state.workspaceId);
      }
      if (!workspacePin) throw new Error("key_directory_pin_required");
      const pinSnapshotId = hasCompleteSnapshotPin(pin) ? pin.latestSnapshotId : null;
      useDelta =
        useDelta &&
        shouldUseDeltaReconnect({
          stateKnownSnapshotId,
          pinSnapshotId,
          hasLastSavedState: state.lastSavedState !== null,
          forceCompleteReconnect: false,
        });
      const knownSnapshotId = useDelta
        ? stateKnownSnapshotId
        : (pinSnapshotId ?? stateKnownSnapshotId);
      const joinParams: Record<string, unknown> = {
        mode: useDelta ? "delta" : "complete",
      };
      if (workspacePin) {
        joinParams.workspaceKeyDirectoryPinSequence = workspacePin.checkpointSequence;
        joinParams.workspaceKeyDirectoryPinHash = workspacePin.checkpointHash;
      }
      if (
        state.access.kind === "share" &&
        state.access.source === "mounted" &&
        state.access.mountId
      ) {
        if (state.access.workspacePinBootstrapHash) {
          joinParams.authenticated_workspace_pin_bootstrap_hash =
            state.access.workspacePinBootstrapHash;
        }
        joinParams.mount_id = state.access.mountId;
        joinParams.share_id = state.access.shareId;
      }
      state._lastJoinMode = useDelta ? "delta" : "complete";
      if (knownSnapshotId) {
        joinParams.knownSnapshotId = knownSnapshotId;
      }
      if (useDelta && stateKnownSnapshotId) {
        joinParams.knownSnapshotUpdateClocks = { ...state.confirmedClocks };
      }
      recordJoinDecision(state, knownSnapshotId, pinSnapshotId, stateKnownSnapshotId, useDelta);
      const popParams =
        state.access.kind === "share"
          ? await getChannelPopParams(
              state.access.participantDeviceId,
              undefined,
              "share",
              getShareParticipantCryptoWorker(state.access.shareSlug),
              buildChannelPopResource(
                documentId,
                "share",
                state.access.authorizationShareId ?? state.access.shareId,
                joinParams,
              ),
            )
          : await getChannelPopParams(
              undefined,
              undefined,
              "user",
              undefined,
              buildChannelPopResource(documentId, "user", undefined, joinParams),
            );
      Object.assign(joinParams, popParams);

      let documentHandled: Promise<void> | null = null;
      let earlyCloseReject: ((err: Error) => void) | null = null;

      const callbacks = buildDocumentChannelCallbacks(
        state,
        documentId,
        localDeviceSigningKeyId,
        failClosed,
        {
          onDocument: (payload) => {
            if (documentHandled) return;
            documentHandled = resumeReconnectDocument(
              payload,
              state,
              documentId,
              localDeviceSigningKeyId,
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
              state.autoSync?.notifyLocalEdit();
            }
          },
          onSyncGap: (err) => {
            void err;
            state._forceCompleteReconnect = true;
            triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
          },
          onError: (reason) => {
            if (
              reason === "document_not_found" ||
              reason === "document_error" ||
              reason === "connection_cap_evict"
            ) {
              failClosed(String(reason));
            } else {
              triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
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
              triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
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
      const channel = await rejoinDocument(
        documentId,
        joinParams,
        callbacks,
        state.stateKey,
        transportScope,
      );
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
      if (isWorkspaceKeyDirectoryRefreshRequired(err)) {
        if (attempt >= MAX_RECONNECT_ATTEMPTS - 1) {
          failClosed(WORKSPACE_KEY_DIRECTORY_REFRESH_REQUIRED);
          return;
        }
        try {
          await refreshWorkspaceKeyDirectoryForDocumentJoin(state, workspaceId);
          useDelta = false;
          state._forceCompleteReconnect = false;
          continue;
        } catch (refreshError) {
          lastError = refreshError;
          if (isTransientReconnectError(refreshError)) {
            useDelta = false;
            continue;
          }
          failClosed("reconnect_failed", refreshError);
          return;
        }
      }
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
        void import("@/shared/lib/offline/storage/store").then(({ deleteOfflineKek }) =>
          deleteOfflineKek(workspaceId).catch(() => {}),
        );
        import("@/shared/lib/notice")
          .then(({ Notice }) => new Notice("Workspace access revoked. Document is now read-only."))
          .catch(() => {});
        return;
      }
      if (reason === "pop_verification_failed") {
        if (state.access.kind === "share" && attempt < MAX_RECONNECT_ATTEMPTS - 1) {
          recordSyncPerf("share_reconnect_pop_verification_retry", {
            documentId,
            attempt,
            joinMode: state._lastJoinMode,
          });
          resetPhoenixConnection("share");
          useDelta = false;
          state._forceCompleteReconnect = false;
          continue;
        }
        failClosed(reason);
        return;
      }
      if (reason === "document_not_found") {
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

  failClosed("reconnect_failed", lastError ?? new Error("Reconnect attempts exhausted"));
}
