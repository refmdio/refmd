import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { getPopHeaders } from "@/shared/lib/pop";
import { buildDeviceKeyCaches } from "./document-verification";
import { getDocumentState, setDocumentError } from "./document-state-cache";
import {
  joinDocument,
  leaveDocument,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import {
  handleDocumentMessage,
  handleRemoteUpdate,
  handleRemoteSnapshot,
  handleUpdateSaved,
  handleUpdateSaveFailed,
  handleSnapshotSaved,
  handleSnapshotSaveFailed,
  type DocumentPayload,
  type UpdateSavedPayload,
  type UpdateSaveFailedPayload,
  type SnapshotSavedPayload,
  type SnapshotSaveFailedPayload,
} from "./ws-handlers";
import { startAutoSync } from "./auto-sync";
import { deviceState } from "@/shared/lib/auth-state";
import type { DocumentState } from "./document-state-cache";

export async function initializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  try {
    await doInitializeDocumentSync(documentId, workspaceId, state);
  } catch (err) {
    state.initPromise = null;
    throw err;
  }
}

async function doInitializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const worker = getCryptoWorker();
  const device = deviceState();
  if (!device) throw new Error("Device state not available");

  const localDeviceSigningPubKey = device.deviceSigningPublic
    ? base64UrlEncode(device.deviceSigningPublic)
    : undefined;

  // 1. KEK resolution
  await resolveActiveKek(workspaceId);

  // 2. DEK resolution + rotation check
  const keysResponse = await encryptionApi.getDocumentKeys(documentId);
  const keys = keysResponse.keys;
  const activeKey = keys.find((k) => k.is_active);

  if (activeKey) {
    await worker.unwrapDek({
      encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
      nonce: base64UrlDecode(activeKey.nonce),
      documentId,
      workspaceId,
      keyVersion: activeKey.key_version,
    });
    state.dekResolved = true;
    state.keyVersion = activeKey.key_version;
  } else {
    throw new Error("No active DEK found for document");
  }

  // DEK rotation completion is Phase 4-22 (requires documentId+keyVersion DEK cache)

  // 3. Build device key cache (signing key membership + TOFU)
  const cacheResult = await buildDeviceKeyCaches(workspaceId);
  if (cacheResult.status === "key_changed") {
    throw new Error(`TOFU key change detected: device ${cacheResult.warning.deviceId}`);
  }
  state.signingKeys = cacheResult.signingKeys;
  state.signingKeyOwners = cacheResult.signingKeyOwners;
  state.revokedSigningKeys = cacheResult.revokedSigningKeys;
  state.rejectedSigningKeys = cacheResult.rejectedSigningKeys;

  // 4. PoP for Channel join
  const popHeaders = await getPopHeaders();
  const joinParams: Record<string, unknown> = {
    pop_challenge: popHeaders["X-PoP-Challenge"],
    pop_signature: popHeaders["X-PoP-Signature"],
    mode: "complete",
  };

  // Send knownSnapshotId from in-memory state (same-session only)
  if (state.activeSnapshotId) {
    joinParams.knownSnapshotId = state.activeSnapshotId;
  }

  // 4. Wait for initial document event
  let documentTimeout: ReturnType<typeof setTimeout> | null = null;
  let rejectDocumentPromise: ((err: Error) => void) | null = null;
  const documentPromise = new Promise<DocumentPayload>((resolve, reject) => {
    rejectDocumentPromise = reject;
    documentTimeout = setTimeout(() => {
      reject(new Error("Timeout waiting for document event"));
    }, 30_000);

    state._onDocumentMessage = (payload: unknown) => {
      clearTimeout(documentTimeout!);
      documentTimeout = null;
      rejectDocumentPromise = null;
      resolve(payload as DocumentPayload);
    };
  });

  // Fail-closed: stop sync + disconnect channel + reject pending init
  function failClosed(reason: string, err?: unknown): void {
    if (err) console.error(`[ws] ${reason}:`, err);
    state.error = reason;
    setDocumentError(documentId, reason);
    if (documentTimeout) clearTimeout(documentTimeout);
    if (rejectDocumentPromise) rejectDocumentPromise(new Error(reason));
    if (state.autoSync) {
      state.autoSync.dispose();
      state.autoSync = null;
    }
    state.sending = false;
    state.pendingSnapshot = null;
    state.pendingUpdateBytes = null;
    leaveDocument(documentId);
    state.channel = null;
    state.initialized = false;
    state.initPromise = null;
  }

  // 5. Channel join
  const callbacks: DocumentChannelCallbacks = {
    onDocument: (payload) => {
      if (state._onDocumentMessage) {
        state._onDocumentMessage(payload as unknown as DocumentPayload);
        state._onDocumentMessage = null;
      }
    },
    onUpdate: (payload) => {
      handleRemoteUpdate(payload as any, state, documentId, localDeviceSigningPubKey).catch(
        (err) => {
          failClosed("verification_failed", err);
        },
      );
    },
    onSnapshot: (payload) => {
      handleRemoteSnapshot(payload as any, state, documentId).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onUpdateSaved: (payload) => {
      handleUpdateSaved(payload as unknown as UpdateSavedPayload, state);
    },
    onUpdateSaveFailed: (payload) => {
      handleUpdateSaveFailed(payload as unknown as UpdateSaveFailedPayload, state);
      const p = payload as unknown as UpdateSaveFailedPayload;
      if (p.requiresNewSnapshot) {
        failClosed("snapshot_mismatch");
      }
    },
    onSnapshotSaved: (payload) => {
      handleSnapshotSaved(payload as unknown as SnapshotSavedPayload, state);
    },
    onSnapshotSaveFailed: (payload) => {
      handleSnapshotSaveFailed(
        payload as unknown as SnapshotSaveFailedPayload,
        state,
        documentId,
      ).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onEphemeralMessage: () => {
      // Ephemeral handling is Phase 4-23
    },
    onUnauthorized: () => {
      failClosed("unauthorized");
    },
    onError: (reason) => {
      if (reason === "document_not_found" || reason === "document_error") {
        failClosed(String(reason));
      } else {
        console.error("[ws] Channel error:", reason);
      }
    },
    onClose: () => {
      // Only fail-closed if state is still alive (not a normal teardown eviction)
      if (state.initialized && getDocumentState(documentId)) {
        failClosed("disconnected");
      }
    },
  };

  let channel;
  try {
    channel = await joinDocument(documentId, joinParams, callbacks);
  } catch (err) {
    if (documentTimeout) clearTimeout(documentTimeout);
    state._onDocumentMessage = null;
    throw err;
  }
  state.channel = channel;

  // Guard: if state was torn down during async init, leave immediately
  if (!getDocumentState(documentId)) {
    leaveDocument(documentId);
    return;
  }

  // 6. Wait for and process initial document data
  let documentPayload: DocumentPayload;
  try {
    documentPayload = await documentPromise;
  } catch (err) {
    failClosed("initial_load_failed", err);
    throw err;
  }
  try {
    await handleDocumentMessage(documentPayload, state, documentId);
  } catch (err) {
    failClosed("initial_load_failed", err);
    throw err;
  }

  // Guard: check again after async message processing
  if (!getDocumentState(documentId)) {
    leaveDocument(documentId);
    return;
  }

  // 7. Derive localClock: find max clock from updates[] for this device
  // (parentSnapshotUpdateClocks values are pre-snapshot; post-snapshot clocks start at 0)
  if (localDeviceSigningPubKey) {
    let maxClock = -1;
    for (const update of documentPayload.updates) {
      if (
        update.publicData.signingPubKey === localDeviceSigningPubKey &&
        update.publicData.clock > maxClock
      ) {
        maxClock = update.publicData.clock;
      }
    }
    state.localClock = maxClock + 1;
  }

  // 8. Start auto-sync
  state.autoSync = startAutoSync(documentId, state);
}

export function teardownDocumentSync(documentId: string, state: DocumentState): void {
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  leaveDocument(documentId);
  state.channel = null;
}
