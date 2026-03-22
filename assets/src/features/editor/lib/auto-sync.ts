import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deviceState } from "@/shared/lib/auth-state";
import { pushUpdate, pushSnapshot } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentState } from "./document-state-cache";

const THROTTLE_MS = 25;
const SNAPSHOT_UPDATE_THRESHOLD = 100;

export interface AutoSyncHandle {
  dispose: () => void;
  notifyLocalEdit: () => void;
}

export function startAutoSync(documentId: string, state: DocumentState): AutoSyncHandle {
  let dirty = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;

  function scheduleSend(): void {
    if (timer || disposed) return;
    timer = setTimeout(async () => {
      timer = null;
      if (disposed) return;
      if (dirty) {
        if (!state.initialized || !state.channel || state.sending || state.error) return;
        dirty = false;
        await sendPendingChanges(documentId, state).catch((err) => {
          console.error("[auto-sync] send failed:", err);
        });
      }
    }, THROTTLE_MS);
  }

  // Watch Y.Doc for changes from local edits (non-remote origin)
  const observer = (_update: Uint8Array, origin: unknown) => {
    if (origin === "remote") return;
    dirty = true;
    scheduleSend();
  };
  state.yDoc.on("update", observer);

  return {
    dispose() {
      disposed = true;
      state.yDoc.off("update", observer);
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    },
    notifyLocalEdit() {
      dirty = true;
      scheduleSend();
    },
  };
}

// ── Send pending changes ─────────────────────────────────────

async function sendPendingChanges(documentId: string, state: DocumentState): Promise<void> {
  if (!state.initialized || !state.channel || state.sending || state.error) return;

  const device = deviceState();
  if (!device?.deviceSigningPublic) return;

  state.sending = true;
  try {
    // Genesis snapshot (first snapshot for new document)
    if (state.activeSnapshotId === null) {
      if (state.pendingSnapshot) {
        state.sending = false;
        return;
      }
      await createAndSendGenesisSnapshot(documentId, state);
      return;
    }

    // Block update sends while snapshot is in flight
    if (state.pendingSnapshot) {
      state.sending = false;
      return;
    }

    // Check if we should create a snapshot first
    if (state.snapshotUpdatesCount >= SNAPSHOT_UPDATE_THRESHOLD) {
      await createAndSendSnapshot(documentId, state);
      return;
    }

    // Compute diff from last saved state
    let updateBytes: Uint8Array;
    if (state.lastSavedState) {
      const tempDoc = new Y.Doc();
      Y.applyUpdate(tempDoc, state.lastSavedState);
      const savedVector = Y.encodeStateVector(tempDoc);
      updateBytes = Y.encodeStateAsUpdate(state.yDoc, savedVector);
      tempDoc.destroy();

      if (updateBytes.length <= 2) {
        state.sending = false;
        return;
      }
    } else {
      updateBytes = Y.encodeStateAsUpdate(state.yDoc);
      if (updateBytes.length <= 2) {
        state.sending = false;
        return;
      }
    }

    const worker = getCryptoWorker();
    const deviceSigningPubKey = base64UrlEncode(device.deviceSigningPublic);
    const deviceId = await worker.getDeviceId();

    // 1. Encrypt
    const { ciphertext, nonce } = await worker.encryptContent({
      plaintext: updateBytes,
      documentId,
      keyVersion: state.keyVersion,
    });
    const ciphertextB64 = base64UrlEncode(ciphertext);
    const nonceB64 = base64UrlEncode(nonce);

    const clock = state.localClock;
    const timestamp = Date.now();

    // 2. Compute update hash (snake_case keys to match server-side JCS)
    const updateHash = await worker.computeUpdateHash({
      clock,
      device_signing_pub_key: deviceSigningPubKey,
      document_id: documentId,
      encrypted_content: ciphertextB64,
      key_version: state.keyVersion,
      nonce: nonceB64,
      ref_snapshot_id: state.activeSnapshotId,
      timestamp,
    });

    // 3. Build public data
    const publicData: Record<string, unknown> = {
      docId: documentId,
      deviceId,
      signingPubKey: deviceSigningPubKey,
      keyVersion: state.keyVersion,
      refSnapshotId: state.activeSnapshotId,
      clock,
      timestamp,
      updateHash,
    };

    // 4. Sign
    const { signature } = await worker.signWsEnvelope({
      prefix: "refmd_update",
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      publicData,
    });

    // 5. Send
    pushUpdate(
      documentId,
      {
        ciphertext: ciphertextB64,
        nonce: nonceB64,
        signature: base64UrlEncode(signature),
        publicData,
      },
      () => {
        state.sending = false;
        state.pendingUpdateBytes = null;
        state.localClock = state.preSendLocalClock;
        if (state.autoSync) state.autoSync.notifyLocalEdit();
      },
    );

    // Save pending update bytes for lastSavedState update on update-saved
    state.pendingUpdateBytes = updateBytes;
    state.preSendLocalClock = state.localClock;
    state.localClock++;
  } catch (err) {
    state.sending = false;
    throw err;
  }
}

// ── Genesis snapshot ─────────────────────────────────────────

async function createAndSendGenesisSnapshot(
  documentId: string,
  state: DocumentState,
): Promise<void> {
  const worker = getCryptoWorker();
  const device = deviceState();
  if (!device?.deviceSigningPublic) return;

  const deviceSigningPubKey = base64UrlEncode(device.deviceSigningPublic);
  const deviceId = await worker.getDeviceId();

  // Encode full Y.Doc state (V2 format)
  const yjsState = Y.encodeStateAsUpdateV2(state.yDoc);
  if (yjsState.length <= 2) {
    state.sending = false;
    return;
  }

  // Encrypt
  const { ciphertext, nonce } = await worker.encryptSnapshot({
    plaintext: yjsState,
    documentId,
    keyVersion: state.keyVersion,
  });
  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);

  // Compute ciphertext hash for proof chain
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(ciphertext));

  // Genesis snapshot: empty parent
  const snapshotId = crypto.randomUUID();
  const publicData: Record<string, unknown> = {
    docId: documentId,
    snapshotId,
    deviceId,
    signingPubKey: deviceSigningPubKey,
    keyVersion: state.keyVersion,
    parentSnapshotId: null,
    parentSnapshotProof: "",
    parentSnapshotUpdateClocks: {},
  };

  // Sign
  const { signature } = await worker.signWsEnvelope({
    prefix: "refmd_snapshot",
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    publicData,
  });

  // Track pending snapshot
  state.pendingSnapshot = {
    snapshotId,
    ciphertextHash,
    parentSnapshotProof: "",
    snapshotYjsState: yjsState,
    knownClocksAtSend: { ...state.knownClocks },
  };

  // Send
  pushSnapshot(
    documentId,
    {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(signature),
      publicData,
    },
    () => {
      state.pendingSnapshot = null;
      state.sending = false;
      if (state.autoSync) state.autoSync.notifyLocalEdit();
    },
  );
}

// ── Threshold snapshot ───────────────────────────────────────

async function createAndSendSnapshot(documentId: string, state: DocumentState): Promise<void> {
  if (!state.activeSnapshotId) {
    state.sending = false;
    return;
  }

  const worker = getCryptoWorker();
  const device = deviceState();
  if (!device?.deviceSigningPublic) return;

  const deviceSigningPubKey = base64UrlEncode(device.deviceSigningPublic);
  const deviceId = await worker.getDeviceId();

  // Encode full Y.Doc state (V2 format)
  const yjsState = Y.encodeStateAsUpdateV2(state.yDoc);

  // Encrypt
  const { ciphertext, nonce } = await worker.encryptSnapshot({
    plaintext: yjsState,
    documentId,
    keyVersion: state.keyVersion,
  });
  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);

  // Compute ciphertext hash
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(ciphertext));

  // Compute parent snapshot proof
  const parentSnapshotProof = await worker.computeSnapshotProof({
    ciphertextHash: state.snapshotCiphertextHash,
    parentProof: state.snapshotProofHash,
    snapshotId: state.activeSnapshotId,
  });

  const snapshotId = crypto.randomUUID();
  const publicData: Record<string, unknown> = {
    docId: documentId,
    snapshotId,
    deviceId,
    signingPubKey: deviceSigningPubKey,
    keyVersion: state.keyVersion,
    parentSnapshotId: state.activeSnapshotId,
    parentSnapshotProof,
    parentSnapshotUpdateClocks: { ...state.knownClocks },
  };

  // Sign
  const { signature } = await worker.signWsEnvelope({
    prefix: "refmd_snapshot",
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    publicData,
  });

  // Track pending snapshot
  state.pendingSnapshot = {
    snapshotId,
    ciphertextHash,
    parentSnapshotProof,
    snapshotYjsState: yjsState,
    knownClocksAtSend: { ...state.knownClocks },
  };

  // Send
  pushSnapshot(
    documentId,
    {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(signature),
      publicData,
    },
    () => {
      state.pendingSnapshot = null;
      state.sending = false;
      if (state.autoSync) state.autoSync.notifyLocalEdit();
    },
  );
}
