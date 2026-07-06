import * as Y from "yjs";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import { hasCompleteSnapshotPin } from "@/shared/lib/anti-rollback/document-state-pins";
import { computeSnapshotProofLinkHash } from "@/shared/lib/anti-rollback/snapshot-proof";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  canonicalMarkdownText,
  clearProseMirrorXml,
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalSyncedStateAsUpdate,
  replaceDocWithCanonicalText,
} from "@/shared/lib/yjs/canonical-document";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  documentOperationAuthorityBoundary,
  rememberVerifiedDocumentOperationAdmission,
  resolveDocumentOperationSigningKeyFromAdmission,
  resolveDocumentWriteSessionSigningKeyFromAdmission,
  verifyDocumentOperationAdmission,
  verifyDocumentOperationAdmissionAncestry,
  verifyDocumentWriteSessionAdmission,
} from "@/shared/lib/document/document-operation-admission";
import type {
  DocumentPayload,
  RemoteSnapshotPayload,
  UpdatePayload,
  WriteSessionPayload,
} from "@/shared/lib/ws/document-payloads";
import {
  lookupCachedSigningKey,
  resolveSigningKey,
  type ResolveSigningKeyResult,
} from "./inbound-signing-keys";
import { notifyDocumentVerifiedContentPreviewReady } from "../../model/document-state/store";
import type { DocumentState } from "../../model/document-state/types";
import { detectDocumentRollback, persistDocumentRollbackPin } from "./inbound-rollback";
import { isRecoverableSyncGapError } from "./error";
import { getDocumentDekCacheKey } from "./share-access";
import { getLocalSigningKeyId } from "./share-identity";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { rememberDocumentAdmissionCheckpoint } from "./outbound-admission";
import { applyInitialPublicationState, queuePublicationAutoSync } from "./outbound-publication";
import { setDocumentReadOnly } from "../../model/document-state/signals";
import { recordSyncPerf } from "./perf";
import { createAdmissionKeyDirectoryRefresh } from "./admission-key-directory";
import { hasCanonicalLocalChanges } from "./inbound-document-decisions";
import {
  checkRotationSnapshot,
  createRollbackAttackError,
  createSyncGapError,
  createVerificationFailedError,
  ensureDekCached,
  rememberVerifiedWriteSessionAdmission,
  resetWriteSessionCountersForSnapshotBaseline,
  throwIfDocumentProcessingCancelled,
  verifyAndDecryptSingleUpdate,
  verifyAndDecryptUpdates,
  verifySnapshotProofChain,
  writeSessionCacheKey,
} from "./inbound-verify-decrypt";
import { nextLocalClockForDevice } from "./local-clock";

function canonicalTextFromUpdate(update: Uint8Array | null): string | null {
  if (!update) return null;
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, update, "remote");
    return canonicalMarkdownText(doc);
  } finally {
    doc.destroy();
  }
}

function canonicalTextAfterApplyingServerDoc(targetDoc: Y.Doc, serverDoc: Y.Doc): string {
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(targetDoc), "remote");
    Y.applyUpdate(doc, encodeCanonicalSyncedStateAsUpdate(serverDoc), "remote");
    clearProseMirrorXml(doc, "remote");
    return canonicalMarkdownText(doc);
  } finally {
    doc.destroy();
  }
}

function replaceLiveWithServerCanonicalDoc(
  state: DocumentState,
  serverDoc: Y.Doc,
  origin: unknown,
): void {
  const serverText = canonicalMarkdownText(serverDoc);
  const serverUpdate = encodeCanonicalSyncedStateAsUpdate(serverDoc);
  const simulatedText = canonicalTextAfterApplyingServerDoc(state.yDoc, serverDoc);
  if (simulatedText === serverText) {
    Y.applyUpdate(state.yDoc, serverUpdate, origin);
    clearProseMirrorXml(state.yDoc, origin);
    return;
  }

  replaceDocWithCanonicalText(state.yDoc, "", origin);
  Y.applyUpdate(state.yDoc, serverUpdate, origin);
  clearProseMirrorXml(state.yDoc, origin);
}

function applyServerCanonicalDocAndLocalDiff(
  perfEvent: "canonical_server_doc_apply" | "canonical_snapshot_doc_apply",
  syncGapMessage:
    | "canonical_structural_merge_unavailable"
    | "canonical_structural_snapshot_merge_unavailable",
  documentId: string,
  state: DocumentState,
  serverDoc: Y.Doc,
  localUpdate: Uint8Array,
  expectedText: string,
  origin: unknown,
): void {
  replaceDocWithCanonicalText(state.yDoc, "", origin);
  Y.applyUpdate(state.yDoc, encodeCanonicalSyncedStateAsUpdate(serverDoc), origin);
  if (localUpdate.length > 2) {
    Y.applyUpdate(state.yDoc, localUpdate, origin);
  }
  clearProseMirrorXml(state.yDoc, origin);
  const actualText = canonicalMarkdownText(state.yDoc);
  if (actualText !== expectedText) {
    recordSyncPerf(perfEvent, {
      documentId,
      mode: "sync-gap",
      liveTextAfterLength: actualText.length,
      expectedTextLength: expectedText.length,
    });
    throw createSyncGapError(syncGapMessage);
  }
}

function applyReencodedServerDocAndLocalText(
  documentId: string,
  state: DocumentState,
  serverDoc: Y.Doc,
  serverText: string,
  liveText: string,
  origin: unknown,
): boolean {
  replaceDocWithCanonicalText(state.yDoc, "", origin);
  Y.applyUpdate(state.yDoc, encodeCanonicalSyncedStateAsUpdate(serverDoc), origin);
  clearProseMirrorXml(state.yDoc, origin);
  if (canonicalMarkdownText(state.yDoc) !== serverText) {
    recordSyncPerf("canonical_rebaseline_local_text_failed", {
      documentId,
      expectedServerTextLength: serverText.length,
      actualServerTextLength: canonicalMarkdownText(state.yDoc).length,
      liveTextLength: liveText.length,
    });
    return false;
  }
  replaceDocWithCanonicalText(state.yDoc, liveText, origin);
  return canonicalMarkdownText(state.yDoc) === liveText;
}

function canonicalLocalDiffAfterApplyingServerDoc(
  liveDoc: Y.Doc,
  serverDoc: Y.Doc,
  savedState: Uint8Array | null,
  savedText: string | null = canonicalTextFromUpdate(savedState),
): { localUpdate: Uint8Array; mergedText: string } | null {
  if (!savedState || savedText === null) return null;
  const liveText = canonicalMarkdownText(liveDoc);
  const localUpdate = encodeCanonicalDiffAsUpdate(liveDoc, savedState);
  if (!localUpdate) return null;
  const mergedDoc = new Y.Doc();
  try {
    Y.applyUpdate(mergedDoc, encodeCanonicalSyncedStateAsUpdate(serverDoc), "remote");
    if (localUpdate.length > 2) Y.applyUpdate(mergedDoc, localUpdate, "local");
    const mergedText = canonicalMarkdownText(mergedDoc);
    const serverText = canonicalMarkdownText(serverDoc);
    if (mergedText !== serverText || liveText === savedText) {
      return { localUpdate, mergedText };
    }
    return null;
  } finally {
    mergedDoc.destroy();
  }
}

function applyCanonicalServerDocToLive(
  documentId: string,
  state: DocumentState,
  serverDoc: Y.Doc,
  origin: unknown,
): { hasMergedLocalChanges: boolean } {
  const serverText = canonicalMarkdownText(serverDoc);
  const liveText = canonicalMarkdownText(state.yDoc);
  const savedText = canonicalTextFromUpdate(state.lastSavedState);
  const hasLocalChanges = hasCanonicalLocalChanges({ savedText, liveText, serverText });
  const simulatedText = canonicalTextAfterApplyingServerDoc(state.yDoc, serverDoc);
  let applyMode = hasLocalChanges ? "yjs-merge" : "yjs-apply";

  if (!hasLocalChanges) {
    replaceLiveWithServerCanonicalDoc(state, serverDoc, origin);
  } else {
    const structuralMerge =
      savedText !== null
        ? canonicalLocalDiffAfterApplyingServerDoc(
            state.yDoc,
            serverDoc,
            state.lastSavedState,
            savedText,
          )
        : null;
    if (structuralMerge === null) {
      if (
        savedText !== null &&
        serverText === savedText &&
        applyReencodedServerDocAndLocalText(
          documentId,
          state,
          serverDoc,
          serverText,
          liveText,
          origin,
        )
      ) {
        applyMode = "server-structs-with-local-text";
      } else {
        recordSyncPerf("canonical_server_doc_apply", {
          documentId,
          mode: "sync-gap",
          savedTextLength: savedText?.length ?? null,
          liveTextBeforeLength: liveText.length,
          serverTextLength: serverText.length,
          liveTextAfterLength: liveText.length,
          simulatedTextLength: simulatedText.length,
          liveMatchesSavedBefore: savedText !== null && liveText === savedText,
          serverMatchesSavedBefore: savedText !== null && serverText === savedText,
          hasMergedLocalChanges: false,
        });
        throw createSyncGapError("canonical_structural_merge_unavailable");
      }
    } else if (simulatedText === structuralMerge.mergedText) {
      Y.applyUpdate(state.yDoc, encodeCanonicalSyncedStateAsUpdate(serverDoc), origin);
      clearProseMirrorXml(state.yDoc, origin);
    } else {
      applyMode = "server-structs-with-local-diff";
      applyServerCanonicalDocAndLocalDiff(
        "canonical_server_doc_apply",
        "canonical_structural_merge_unavailable",
        documentId,
        state,
        serverDoc,
        structuralMerge.localUpdate,
        structuralMerge.mergedText,
        origin,
      );
    }
  }
  recordSyncPerf("canonical_server_doc_apply", {
    documentId,
    mode: applyMode,
    savedTextLength: savedText?.length ?? null,
    liveTextBeforeLength: liveText.length,
    serverTextLength: serverText.length,
    liveTextAfterLength: canonicalMarkdownText(state.yDoc).length,
    simulatedTextLength: simulatedText.length,
    liveMatchesSavedBefore: savedText !== null && liveText === savedText,
    serverMatchesSavedBefore: savedText !== null && serverText === savedText,
    hasMergedLocalChanges: hasLocalChanges,
  });
  return { hasMergedLocalChanges: hasLocalChanges };
}

function applyCanonicalSnapshotDocToLive(
  documentId: string,
  state: DocumentState,
  serverDoc: Y.Doc,
  origin: unknown,
): { hasMergedLocalChanges: boolean } {
  const serverText = canonicalMarkdownText(serverDoc);
  const liveText = canonicalMarkdownText(state.yDoc);
  const savedText = canonicalTextFromUpdate(state.lastSavedState);
  const hasLocalChanges = hasCanonicalLocalChanges({ savedText, liveText, serverText });
  const simulatedText = canonicalTextAfterApplyingServerDoc(state.yDoc, serverDoc);
  let applyMode = hasLocalChanges ? "yjs-merge" : "server-struct-replace";

  if (hasLocalChanges) {
    const structuralMerge =
      savedText !== null
        ? canonicalLocalDiffAfterApplyingServerDoc(
            state.yDoc,
            serverDoc,
            state.lastSavedState,
            savedText,
          )
        : null;
    if (structuralMerge === null) {
      if (
        savedText !== null &&
        serverText === savedText &&
        applyReencodedServerDocAndLocalText(
          documentId,
          state,
          serverDoc,
          serverText,
          liveText,
          origin,
        )
      ) {
        applyMode = "server-structs-with-local-text";
      } else {
        recordSyncPerf("canonical_snapshot_doc_apply", {
          documentId,
          mode: "sync-gap",
          savedTextLength: savedText?.length ?? null,
          liveTextBeforeLength: liveText.length,
          serverTextLength: serverText.length,
          liveTextAfterLength: liveText.length,
          simulatedTextLength: simulatedText.length,
          hasMergedLocalChanges: false,
        });
        throw createSyncGapError("canonical_structural_snapshot_merge_unavailable");
      }
    } else if (simulatedText === structuralMerge.mergedText) {
      Y.applyUpdate(state.yDoc, encodeCanonicalSyncedStateAsUpdate(serverDoc), origin);
      clearProseMirrorXml(state.yDoc, origin);
    } else {
      applyMode = "server-structs-with-local-diff";
      applyServerCanonicalDocAndLocalDiff(
        "canonical_snapshot_doc_apply",
        "canonical_structural_snapshot_merge_unavailable",
        documentId,
        state,
        serverDoc,
        structuralMerge.localUpdate,
        structuralMerge.mergedText,
        origin,
      );
    }
  } else {
    replaceLiveWithServerCanonicalDoc(state, serverDoc, origin);
  }
  recordSyncPerf("canonical_snapshot_doc_apply", {
    documentId,
    mode: applyMode,
    savedTextLength: savedText?.length ?? null,
    liveTextBeforeLength: liveText.length,
    serverTextLength: serverText.length,
    liveTextAfterLength: canonicalMarkdownText(state.yDoc).length,
    simulatedTextLength: simulatedText.length,
    hasMergedLocalChanges: hasLocalChanges,
  });
  return { hasMergedLocalChanges: hasLocalChanges };
}

function markMergedLocalChangesForSync(state: DocumentState): void {
  state._preAutoSyncUserEdit = true;
  state.autoSync?.notifyLocalEdit();
}

// ── Initial document load ────────────────────────────────────
// Pattern: decrypt all async FIRST, then apply atomically in transact

export async function handleDocumentMessage(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  const startedAt = performance.now();
  recordSyncPerf("initial_document_received", {
    documentId,
    hasSnapshot: payload.snapshot !== null,
    updateCount: payload.updates.length,
    latestVersion: payload.latestVersion,
  });
  throwIfDocumentProcessingCancelled(state);
  applyInitialPublicationState(documentId, state, payload.publicState);
  if (typeof payload.authorityPermissionVersion === "number") {
    state.authorityPermissionVersion = payload.authorityPermissionVersion;
  }
  if (typeof payload.readOnly === "boolean") {
    setDocumentReadOnly(state.stateKey, payload.readOnly);
  }
  const worker = getDocumentCryptoWorker(state);
  const pin = await detectDocumentRollback(payload, state, documentId);
  recordSyncPerf("initial_rollback_checked", {
    documentId,
    elapsedMs: performance.now() - startedAt,
  });

  // Decrypt snapshot before entering the transaction.
  let decryptedSnapshot: Uint8Array | null = null;
  let snapshotMeta: {
    snapshotId: string;
    parentProofHash: string;
    parentSnapshotUpdateClocks: Record<string, number>;
    ciphertextHash: string;
    proofHash: string;
  } | null = null;

  if (payload.snapshot) {
    const snap = payload.snapshot;
    throwIfDocumentProcessingCancelled(state);

    recordSyncPerf("initial_snapshot_signing_key_start", {
      documentId,
      signingKeyId: snap.publicData.signingKeyId,
      elapsedMs: performance.now() - startedAt,
    });
    const { keyResult, admissionAncestryVerified } = await resolveSnapshotSigningKey(snap, state, {
      includeHistorical: true,
    });
    recordSyncPerf("initial_snapshot_signing_key_resolved", {
      documentId,
      signingKeyId: snap.publicData.signingKeyId,
      status: keyResult.status,
      admissionAncestryVerified,
      elapsedMs: performance.now() - startedAt,
    });
    if (keyResult.status === "key_changed") {
      throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
    }
    if (
      keyResult.status === "not_found" &&
      state.rejectedSigningKeys.has(snap.publicData.signingKeyId)
    ) {
      throw createVerificationFailedError(
        `Snapshot: rejected signing key (cross-sign failed) ${snap.publicData.signingKeyId}`,
      );
    }
    if (keyResult.status === "not_found") {
      throw createVerificationFailedError(
        `Snapshot: unknown signing key ${snap.publicData.signingKeyId}`,
      );
    }
    // Signature verification is mandatory once the signing key is resolved.
    if (keyResult.status === "found") {
      recordSyncPerf("initial_snapshot_signature_verify_start", {
        documentId,
        elapsedMs: performance.now() - startedAt,
      });
      const valid = await verifyDocumentSnapshotSignature(
        snap,
        keyResult.key,
        keyResult.ownerId,
        worker,
        state.workspaceId,
      );
      recordSyncPerf("initial_snapshot_signature_verified", {
        documentId,
        valid,
        elapsedMs: performance.now() - startedAt,
      });
      if (!valid) {
        throw createVerificationFailedError("Snapshot signature verification failed");
      }
    }
    if (!payload.snapshotAdmissionEventHash) {
      throw createVerificationFailedError("Snapshot admission event hash missing");
    }
    recordSyncPerf("initial_snapshot_proof_start", {
      documentId,
      elapsedMs: performance.now() - startedAt,
    });
    const snapshotProof = await computeReceivedSnapshotProof(
      worker,
      snap,
      payload.snapshotAdmissionEventHash,
    );
    recordSyncPerf("initial_snapshot_proof_ready", {
      documentId,
      elapsedMs: performance.now() - startedAt,
    });
    try {
      recordSyncPerf("initial_snapshot_admission_verify_start", {
        documentId,
        elapsedMs: performance.now() - startedAt,
      });
      await verifyDocumentOperationAdmission({
        admission: snap.admission,
        eventType: "document_snapshot_accepted",
        publicData: snap.publicData,
        workspaceId: state.workspaceId,
        documentId,
        operationHash: snapshotProof.ciphertextHash,
        signature: snap.signature,
        actorUserId: keyResult.ownerId,
        expectedAdmissionEventHash: payload.snapshotAdmissionEventHash,
      });
      if (!admissionAncestryVerified) {
        await verifyDocumentOperationAdmissionAncestry({
          admission: snap.admission,
          workspaceId: state.workspaceId,
          refreshKeyDirectory: createAdmissionKeyDirectoryRefresh(state, documentId),
        });
      }
      recordSyncPerf("initial_snapshot_admission_verified", {
        documentId,
        elapsedMs: performance.now() - startedAt,
      });
    } catch (err) {
      throw createVerificationFailedError(
        err instanceof Error ? err.message : "Snapshot admission verification failed",
      );
    }
    if (payload.ciphertextHash && payload.ciphertextHash !== snapshotProof.ciphertextHash) {
      throw createVerificationFailedError("Snapshot ciphertextHash metadata mismatch");
    }
    if (payload.proofChainHash && payload.proofChainHash !== snapshotProof.proofChainHash) {
      throw createVerificationFailedError("Snapshot proofChainHash metadata mismatch");
    }

    // Step 3c: parentProofHash verification via snapshotProofChain
    // Snapshot ID and proof must come from the same baseline.
    const stateAnchor =
      state.activeSnapshotId && state.snapshotProofHash && state.snapshotCiphertextHash
        ? { snapshotId: state.activeSnapshotId, proofHash: state.snapshotProofHash }
        : null;
    const pinAnchor = hasCompleteSnapshotPin(pin)
      ? { snapshotId: pin.latestSnapshotId, proofHash: pin.latestSnapshotProofHash }
      : null;
    const anchor = pinAnchor ?? stateAnchor;
    if (anchor) {
      const snapshotChanged = snap.publicData.snapshotId !== anchor.snapshotId;

      if (snapshotChanged && payload.snapshotProofChain.length === 0) {
        // Fail-closed: pin exists, snapshot changed, but no proof chain.
        throw createRollbackAttackError(
          "Snapshot changed but no proof chain provided (rollback attack)",
        );
      }

      if (snapshotChanged && payload.snapshotProofChain.length > 0) {
        // anchorProofHash IS the computed proof for the anchor snapshot.
        // Chain head's parentProofHash should match this directly.
        await verifySnapshotProofChain(
          payload.snapshotProofChain,
          snap.publicData.parentProofHash,
          anchor.proofHash,
          snap.publicData.snapshotId,
          snapshotProof.ciphertextHash,
          snapshotProof.signatureHash,
          payload.snapshotAdmissionEventHash,
        );
      }
    } else if (payload.snapshotProofChain.length > 0) {
      await verifySnapshotProofChain(
        payload.snapshotProofChain,
        snap.publicData.parentProofHash,
        "GENESIS",
        snap.publicData.snapshotId,
        snapshotProof.ciphertextHash,
        snapshotProof.signatureHash,
        payload.snapshotAdmissionEventHash,
      );
    }
    recordSyncPerf("initial_snapshot_verified", {
      documentId,
      elapsedMs: performance.now() - startedAt,
    });

    // Step 3d: AEAD decryption
    throwIfDocumentProcessingCancelled(state);
    const snapshotCiphertext = base64UrlDecode(snap.ciphertext);
    await ensureDekCached(documentId, state.workspaceId, snap.publicData.keyVersion, state);
    decryptedSnapshot = await worker.decryptSnapshot({
      ciphertext: snapshotCiphertext,
      nonce: base64UrlDecode(snap.nonce),
      documentId,
      keyVersion: snap.publicData.keyVersion,
      cacheKey: getDocumentDekCacheKey(state, documentId),
    });
    recordSyncPerf("initial_snapshot_decrypted", {
      documentId,
      elapsedMs: performance.now() - startedAt,
      ciphertextBytes: snapshotCiphertext.byteLength,
    });

    snapshotMeta = {
      snapshotId: snap.publicData.snapshotId,
      parentProofHash: snap.publicData.parentProofHash,
      parentSnapshotUpdateClocks: snap.publicData.parentSnapshotUpdateClocks,
      ciphertextHash: snapshotProof.ciphertextHash,
      proofHash: snapshotProof.proofChainHash,
    };
  }

  // Prepare state for update verification without committing to permanent state yet
  const prevActiveSnapshotId = state.activeSnapshotId;
  const prevKnownClocks = { ...state.knownClocks };
  const prevConfirmedClocks = { ...state.confirmedClocks };
  const prevWriteSessionCounters = { ...state.writeSessionCounters };
  const prevSnapshotBaseClocks = { ...state.snapshotBaseClocks };

  if (snapshotMeta) {
    state.activeSnapshotId = snapshotMeta.snapshotId;
    state.snapshotBaseClocks = { ...snapshotMeta.parentSnapshotUpdateClocks };
    state.knownClocks = { ...snapshotMeta.parentSnapshotUpdateClocks };
    state.confirmedClocks = { ...snapshotMeta.parentSnapshotUpdateClocks };
    resetWriteSessionCountersForSnapshotBaseline(state);
    state._pendingOutOfOrderUpdates = [];
    clearOutOfOrderGapTimeout(state);
  }

  // Verify and decrypt all updates before entering the transaction.
  let decryptedUpdates: Awaited<ReturnType<typeof verifyAndDecryptUpdates>>;
  try {
    decryptedUpdates = await verifyAndDecryptUpdates(
      payload.updates,
      state,
      documentId,
      false,
      true,
    );
    recordSyncPerf("initial_updates_verified", {
      documentId,
      elapsedMs: performance.now() - startedAt,
      updateCount: payload.updates.length,
    });
  } catch (err) {
    // Rollback temporary state on verification failure
    state.activeSnapshotId = prevActiveSnapshotId;
    state.knownClocks = prevKnownClocks;
    state.confirmedClocks = prevConfirmedClocks;
    state.writeSessionCounters = prevWriteSessionCounters;
    state.snapshotBaseClocks = prevSnapshotBaseClocks;
    throw err;
  }

  // Version regression check BEFORE applying to Y.Doc (fail-closed)
  let effectiveVersion = payload.latestVersion;
  for (const update of payload.updates) {
    if (update.version > effectiveVersion) effectiveVersion = update.version;
  }
  if (state.latestVersion > 0 && effectiveVersion < state.latestVersion) {
    state.activeSnapshotId = prevActiveSnapshotId;
    state.knownClocks = prevKnownClocks;
    state.confirmedClocks = prevConfirmedClocks;
    state.writeSessionCounters = prevWriteSessionCounters;
    state.snapshotBaseClocks = prevSnapshotBaseClocks;
    throw createRollbackAttackError("Version regression detected");
  }

  // Rebuild the server baseline in a side document, then apply the server
  // Yjs structs into the live editor doc so local CRDT edits can compose.
  const isDeltaSameSnapshot = !payload.snapshot && state.activeSnapshotId !== null;
  const serverDoc = new Y.Doc();
  if (decryptedSnapshot) {
    Y.applyUpdateV2(serverDoc, decryptedSnapshot, "remote");
  } else if (isDeltaSameSnapshot && state.lastSavedState) {
    Y.applyUpdate(serverDoc, state.lastSavedState, "remote");
  }
  for (const { decrypted } of decryptedUpdates) {
    Y.applyUpdate(serverDoc, decrypted, "remote");
  }

  // Apply atomically inside the transaction without awaits.
  let appliedCanonicalResult: { hasMergedLocalChanges: boolean } = {
    hasMergedLocalChanges: false,
  };
  state._applyingRemote = true;
  try {
    appliedCanonicalResult = decryptedSnapshot
      ? applyCanonicalSnapshotDocToLive(documentId, state, serverDoc, "remote")
      : applyCanonicalServerDocToLive(documentId, state, serverDoc, "remote");
  } finally {
    state._applyingRemote = false;
  }
  recordSyncPerf("initial_document_applied", {
    documentId,
    elapsedMs: performance.now() - startedAt,
    updateCount: payload.updates.length,
  });
  notifyDocumentVerifiedContentPreviewReady(state);
  recordSyncPerf("initial_verified_content_preview_ready", {
    documentId,
    elapsedMs: performance.now() - startedAt,
    updateCount: payload.updates.length,
  });

  // Commit snapshot metadata after successful verification + application.
  if (snapshotMeta) {
    state.snapshotProofHash = snapshotMeta.proofHash;
    state.snapshotCiphertextHash = snapshotMeta.ciphertextHash;
  }

  // Build lastSavedState from server data only (decoded snapshot + updates, not live Y.Doc).
  // For same-snapshot delta reconnect (snapshot: null, already initialized),
  // preserve existing lastSavedState and update count — only apply delta to Y.Doc.
  if (!isDeltaSameSnapshot) {
    state.lastSavedState = encodeCanonicalSyncedStateAsUpdate(serverDoc);
    state.snapshotUpdatesCount = payload.updates.length;
  } else {
    // Delta reconnect: update lastSavedState incrementally with delta updates
    if (state.lastSavedState && decryptedUpdates.length > 0) {
      const trackingDoc = new Y.Doc();
      Y.applyUpdate(trackingDoc, state.lastSavedState, "remote");
      for (const { decrypted } of decryptedUpdates) {
        Y.applyUpdate(trackingDoc, decrypted, "remote");
      }
      state.lastSavedState = encodeCanonicalSyncedStateAsUpdate(trackingDoc);
      trackingDoc.destroy();
    }
    state.snapshotUpdatesCount += payload.updates.length;
  }
  serverDoc.destroy();
  if (appliedCanonicalResult.hasMergedLocalChanges) {
    markMergedLocalChangesForSync(state);
  }
  recordSyncPerf("initial_saved_baseline_ready", {
    documentId,
    elapsedMs: performance.now() - startedAt,
    updateCount: payload.updates.length,
  });
  state.latestVersion = effectiveVersion;

  // Advance keyVersion to the highest version seen in initial data
  if (payload.snapshot && payload.snapshot.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = payload.snapshot.publicData.keyVersion;
  }
  for (const update of payload.updates) {
    if (update.publicData.keyVersion > state.keyVersion) {
      state.keyVersion = update.publicData.keyVersion;
    }
  }

  // Persist anti-rollback pin
  persistDocumentRollbackPin(documentId, state);
  rememberDocumentAdmissionCheckpoint(state, payload.snapshot);
  for (const update of payload.updates) {
    rememberDocumentAdmissionCheckpoint(state, update);
  }

  state.initialized = true;
  notifyDocumentVerifiedContentPreviewReady(state);
  recordSyncPerf("initial_document_ready", {
    documentId,
    elapsedMs: performance.now() - startedAt,
    updateCount: payload.updates.length,
  });
  queuePublicationAutoSync(documentId, state);
}

export async function handleRemoteWriteSession(
  payload: WriteSessionPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  if (!state.initialized) {
    state._pendingRemoteEvents.push({ type: "write-session", payload });
    return;
  }

  throwIfDocumentProcessingCancelled(state);
  const cacheKey = writeSessionCacheKey(payload.publicData);
  const pendingVerification = state.pendingVerifiedWriteSessions.get(cacheKey);
  if (pendingVerification) {
    return;
  }
  recordSyncPerf("write_session_broadcast_received", {
    documentId,
    signingKeyId: payload.publicData.signingKeyId,
    writeSessionEventHash: payload.publicData.writeSessionEventHash,
  });
  const startedAt = performance.now();

  const verification = (async () => {
    recordSyncPerf("write_session_broadcast_ancestry_start", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
    });
    await verifyDocumentOperationAdmissionAncestry({
      admission: payload.admission,
      workspaceId: state.workspaceId,
      refreshKeyDirectory: createAdmissionKeyDirectoryRefresh(state, documentId),
    });
    recordSyncPerf("write_session_broadcast_ancestry_ready", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
      elapsedMs: performance.now() - startedAt,
    });
    const admittedKey = resolveDocumentWriteSessionSigningKeyFromAdmission({
      admission: payload.admission,
      publicData: payload.publicData,
    });
    if (!admittedKey) {
      throw new Error("write_session_signing_key_unresolved");
    }
    recordSyncPerf("write_session_broadcast_key_ready", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
      elapsedMs: performance.now() - startedAt,
    });
    state.signingKeys.set(payload.publicData.signingKeyId, admittedKey.key);
    state.signingKeyOwners.set(payload.publicData.signingKeyId, admittedKey.actorUserId);
    await verifyDocumentWriteSessionAdmission({
      admission: payload.admission,
      publicData: payload.publicData,
      workspaceId: state.workspaceId,
      documentId,
      actorUserId: admittedKey.actorUserId,
      allowPrewarmCounterZero: true,
    });
    recordSyncPerf("write_session_broadcast_admission_ready", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
      elapsedMs: performance.now() - startedAt,
    });
    rememberVerifiedDocumentOperationAdmission({
      admission: payload.admission,
      workspaceId: state.workspaceId,
    });
    await rememberVerifiedWriteSessionAdmission({
      payload,
      state,
      documentId,
      actorUserId: admittedKey.actorUserId,
    });
    recordSyncPerf("write_session_broadcast_cache_ready", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
      elapsedMs: performance.now() - startedAt,
    });
    rememberDocumentAdmissionCheckpoint(state, payload);
    recordSyncPerf("write_session_broadcast_verified", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
      elapsedMs: performance.now() - startedAt,
    });
  })().catch((err) => {
    const wrapped = createVerificationFailedError(
      err instanceof Error ? err.message : "Write session broadcast verification failed",
    );
    recordSyncPerf("write_session_broadcast_failed", {
      documentId,
      signingKeyId: payload.publicData.signingKeyId,
      writeSessionEventHash: payload.publicData.writeSessionEventHash,
      error: wrapped.message,
    });
    throw wrapped;
  });

  state.pendingVerifiedWriteSessions.set(cacheKey, verification);
  void verification
    .finally(() => {
      if (state.pendingVerifiedWriteSessions.get(cacheKey) !== verification) return;
      state.pendingVerifiedWriteSessions.delete(cacheKey);
    })
    .catch(() => {});
}

// ── Remote update ────────────────────────────────────────────

export async function handleRemoteUpdate(
  payload: UpdatePayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningKeyId?: string,
  onDeferredVerificationFailed?: (err: unknown) => void,
): Promise<void> {
  const receivedAt = performance.now();
  recordSyncPerf("remote_update_received", {
    documentId,
    updateHash: payload.publicData.updateHash,
    version: payload.version,
  });
  if (!state.initialized) {
    state._pendingRemoteEvents.push({ type: "update", payload });
    return;
  }

  // Reject updates from revoked devices on live path
  if (state.revokedSigningKeys.has(payload.publicData.signingKeyId)) {
    throw new Error(`Rejected live update from revoked device ${payload.publicData.signingKeyId}`);
  }

  // Verify and decrypt (single decryption — includes refSnapshotId + TOFU + signature)
  let result: Awaited<ReturnType<typeof verifyAndDecryptSingleUpdate>>;
  try {
    result = await verifyAndDecryptSingleUpdate(payload, state, documentId, false, false, false);
  } catch (err) {
    if (isRecoverableSyncGapError(err)) {
      enqueueOutOfOrderUpdate(state, payload);
      return;
    }
    throw err;
  }
  if (!result) return; // stale/duplicate
  recordSyncPerf("remote_update_verified", {
    documentId,
    updateHash: payload.publicData.updateHash,
    elapsedMs: performance.now() - receivedAt,
  });

  const trackingDoc = new Y.Doc();
  if (state.lastSavedState) {
    Y.applyUpdate(trackingDoc, state.lastSavedState, "remote");
  }
  Y.applyUpdate(trackingDoc, result.decrypted, "remote");
  const savedTextBeforeUpdate = canonicalTextFromUpdate(state.lastSavedState);
  const trackedTextAfterUpdate = canonicalMarkdownText(trackingDoc);
  if (
    savedTextBeforeUpdate !== null &&
    trackedTextAfterUpdate === savedTextBeforeUpdate &&
    result.decrypted.length > 2
  ) {
    recordSyncPerf("remote_update_no_canonical_progress", {
      documentId,
      updateHash: payload.publicData.updateHash,
      savedTextLength: savedTextBeforeUpdate.length,
      decryptedBytes: result.decrypted.length,
    });
  }

  let appliedCanonicalResult: { hasMergedLocalChanges: boolean } = {
    hasMergedLocalChanges: false,
  };
  state._applyingRemote = true;
  try {
    appliedCanonicalResult = applyCanonicalServerDocToLive(
      documentId,
      state,
      trackingDoc,
      "remote",
    );
  } finally {
    state._applyingRemote = false;
  }
  recordSyncPerf("remote_update_applied", {
    documentId,
    updateHash: payload.publicData.updateHash,
    elapsedMs: performance.now() - receivedAt,
  });
  notifyRemoteContentReady(state, documentId);
  if (result.startDeferredVerification) {
    scheduleDeferredRemoteUpdateVerification(result.startDeferredVerification)
      .then(() => {
        recordSyncPerf("remote_update_deferred_hybrid_verified", {
          documentId,
          updateHash: payload.publicData.updateHash,
          elapsedMs: performance.now() - receivedAt,
        });
      })
      .catch((err) => {
        recordSyncPerf("remote_update_deferred_hybrid_failed", {
          documentId,
          updateHash: payload.publicData.updateHash,
          error: err instanceof Error ? err.message : String(err),
          elapsedMs: performance.now() - receivedAt,
        });
        onDeferredVerificationFailed?.(err);
      });
  }

  // Update clocks
  state.knownClocks[result.deviceKey] = result.clock;
  state.confirmedClocks[result.deviceKey] = result.clock;

  // Update lastSavedState: reuse decrypted bytes (no re-decryption)
  state.lastSavedState = encodeCanonicalSyncedStateAsUpdate(trackingDoc);
  trackingDoc.destroy();
  if (appliedCanonicalResult.hasMergedLocalChanges) {
    markMergedLocalChangesForSync(state);
  }

  // Invalidate pre-send rollback state since server baseline has advanced

  if (payload.version > state.latestVersion) {
    state.latestVersion = payload.version;
  }
  state.snapshotUpdatesCount++;

  // Persist anti-rollback pin (version update)
  persistDocumentRollbackPin(documentId, state);
  rememberDocumentAdmissionCheckpoint(state, payload);

  // If this update is from our own device, advance localClock
  if (localDeviceSigningKeyId && payload.publicData.signingKeyId === localDeviceSigningKeyId) {
    if (payload.publicData.clock >= state.localClock) {
      state.localClock = payload.publicData.clock + 1;
    }
  }

  void state.autoSync?.prepareWriteSession();
  await drainOutOfOrderUpdates(state, documentId, localDeviceSigningKeyId);
}

function scheduleDeferredRemoteUpdateVerification(start: () => Promise<void>): Promise<void> {
  if (typeof window === "undefined") {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        start().then(resolve, reject);
      }, 1_250);
    });
  }
  return new Promise((resolve, reject) => {
    const run = () => {
      start().then(resolve, reject);
    };
    const scheduleIdle =
      window.requestIdleCallback ??
      ((callback: IdleRequestCallback, options?: IdleRequestOptions) =>
        window.setTimeout(
          () =>
            callback({
              didTimeout: true,
              timeRemaining: () => 0,
            }),
          options?.timeout ?? 1_250,
        ));
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        window.setTimeout(() => {
          scheduleIdle(run, { timeout: 1_250 });
        }, 1_250);
      });
    });
  });
}

function notifyRemoteContentReady(state: DocumentState, documentId: string): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent("refmd:document-remote-content-ready", {
      detail: {
        documentId,
        stateKey: state.stateKey,
      },
    }),
  );
}

function enqueueOutOfOrderUpdate(state: DocumentState, payload: UpdatePayload): void {
  const exists = state._pendingOutOfOrderUpdates.some(
    (queued) =>
      queued.publicData.refSnapshotId === payload.publicData.refSnapshotId &&
      queued.publicData.signingKeyId === payload.publicData.signingKeyId &&
      queued.publicData.clock === payload.publicData.clock,
  );
  if (!exists) {
    state._pendingOutOfOrderUpdates.push(payload);
  }
  scheduleOutOfOrderGapTimeout(state);
}

function scheduleOutOfOrderGapTimeout(state: DocumentState): void {
  if (state._syncGapTimer) return;
  state._syncGapTimer = setTimeout(() => {
    state._syncGapTimer = null;
    if (state._pendingOutOfOrderUpdates.length === 0) return;

    const first = state._pendingOutOfOrderUpdates[0]!;
    state._onRecoverableSyncGap?.(
      createSyncGapError(
        `Out-of-order update did not resolve: device=${first.publicData.signingKeyId} clock=${first.publicData.clock}`,
      ),
    );
  }, 2_000);
}

function clearOutOfOrderGapTimeout(state: DocumentState): void {
  if (!state._syncGapTimer) return;
  clearTimeout(state._syncGapTimer);
  state._syncGapTimer = null;
}

async function drainOutOfOrderUpdates(
  state: DocumentState,
  documentId: string,
  localDeviceSigningKeyId?: string,
): Promise<void> {
  if (state._drainingOutOfOrderUpdates) return;
  state._drainingOutOfOrderUpdates = true;
  try {
    let progressed = true;
    while (progressed) {
      progressed = false;
      state._pendingOutOfOrderUpdates.sort(
        (a, b) =>
          a.publicData.signingKeyId.localeCompare(b.publicData.signingKeyId) ||
          a.publicData.clock - b.publicData.clock,
      );

      for (let index = 0; index < state._pendingOutOfOrderUpdates.length; index += 1) {
        const queued = state._pendingOutOfOrderUpdates[index]!;
        const queuedClockKey = documentClockKey(queued.publicData);
        const lastClock = state.knownClocks[queuedClockKey];
        const expectedClock = lastClock === undefined ? 0 : lastClock + 1;
        if (
          queued.publicData.refSnapshotId === state.activeSnapshotId &&
          queued.publicData.clock === expectedClock
        ) {
          state._pendingOutOfOrderUpdates.splice(index, 1);
          await handleRemoteUpdate(queued, state, documentId, localDeviceSigningKeyId);
          progressed = true;
          break;
        }
      }
    }
    if (state._pendingOutOfOrderUpdates.length === 0) {
      clearOutOfOrderGapTimeout(state);
    }
  } finally {
    state._drainingOutOfOrderUpdates = false;
  }
}

// ── Remote snapshot ──────────────────────────────────────────

export async function handleRemoteSnapshot(
  payload: RemoteSnapshotPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  if (!state.initialized) {
    state._pendingRemoteEvents.push({ type: "snapshot", payload });
    return;
  }

  if (state.revokedSigningKeys.has(payload.snapshot.publicData.signingKeyId)) {
    throw new Error(
      `Rejected live snapshot from revoked device ${payload.snapshot.publicData.signingKeyId}`,
    );
  }

  const worker = getDocumentCryptoWorker(state);
  const snap = payload.snapshot;
  const previousActiveSnapshotId = state.activeSnapshotId;
  if (snap.publicData.snapshotId === state.activeSnapshotId) {
    return;
  }

  const { keyResult, admissionAncestryVerified } = await resolveSnapshotSigningKey(snap, state);
  if (keyResult.status === "key_changed") {
    throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    throw createVerificationFailedError(
      `Remote snapshot: unknown signing key ${snap.publicData.signingKeyId}`,
    );
  }

  // Verify parentSnapshotId matches current active snapshot
  if (
    state.activeSnapshotId !== null &&
    snap.publicData.parentSnapshotId !== state.activeSnapshotId
  ) {
    throw createSyncGapError(
      `Remote snapshot: parentSnapshotId mismatch (expected=${state.activeSnapshotId}, got=${snap.publicData.parentSnapshotId})`,
    );
  }

  if (state.activeSnapshotId === null && snap.publicData.parentSnapshotId !== "GENESIS") {
    throw createVerificationFailedError("Remote snapshot: genesis parentSnapshotId invalid");
  }

  // Verify parentProofHash matches the current active snapshot's proof hash.
  // state.snapshotProofHash IS the computed proof for the current active snapshot.
  // The new snapshot's parentProofHash should match it directly.
  if (state.activeSnapshotId !== null && state.snapshotProofHash && state.snapshotCiphertextHash) {
    if (snap.publicData.parentProofHash !== state.snapshotProofHash) {
      throw createVerificationFailedError("Remote snapshot: parentProofHash verification failed");
    }
  }

  const valid = await verifyDocumentSnapshotSignature(
    snap,
    keyResult.key,
    keyResult.ownerId,
    worker,
    state.workspaceId,
  );
  if (!valid) {
    throw createVerificationFailedError("Remote snapshot signature verification failed");
  }

  if (!payload.snapshotAdmissionEventHash) {
    throw createVerificationFailedError("Remote snapshot: admission event hash missing");
  }
  const remoteProof = await computeReceivedSnapshotProof(
    worker,
    snap,
    payload.snapshotAdmissionEventHash,
  );
  const remoteCiphertextHash = remoteProof.ciphertextHash;
  try {
    await verifyDocumentOperationAdmission({
      admission: snap.admission,
      eventType: "document_snapshot_accepted",
      publicData: snap.publicData,
      workspaceId: state.workspaceId,
      documentId,
      operationHash: remoteCiphertextHash,
      signature: snap.signature,
      actorUserId: keyResult.ownerId,
      expectedAdmissionEventHash: payload.snapshotAdmissionEventHash,
    });
    if (!admissionAncestryVerified) {
      await verifyDocumentOperationAdmissionAncestry({
        admission: snap.admission,
        workspaceId: state.workspaceId,
        refreshKeyDirectory: createAdmissionKeyDirectoryRefresh(state, documentId),
      });
    }
  } catch (err) {
    throw createVerificationFailedError(
      err instanceof Error ? err.message : "Remote snapshot admission verification failed",
    );
  }
  if (
    !payload.proofChainHash ||
    payload.ciphertextHash !== remoteCiphertextHash ||
    payload.proofChainHash !== remoteProof.proofChainHash
  ) {
    throw createVerificationFailedError("Remote snapshot: proof metadata missing or mismatched");
  }

  await ensureDekCached(documentId, state.workspaceId, snap.publicData.keyVersion, state);
  const decrypted = await worker.decryptSnapshot({
    ciphertext: base64UrlDecode(snap.ciphertext),
    nonce: base64UrlDecode(snap.nonce),
    documentId,
    keyVersion: snap.publicData.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });

  if (state.activeSnapshotId !== previousActiveSnapshotId) {
    if (snap.publicData.snapshotId === state.activeSnapshotId) return;
    throw createSyncGapError(
      `Remote snapshot: active snapshot changed during verification (expected=${previousActiveSnapshotId}, got=${state.activeSnapshotId})`,
    );
  }

  const queuedBeforeSnapshot = state._pendingOutOfOrderUpdates;
  const retainedQueuedUpdates = queuedBeforeSnapshot.filter(
    (update) => update.publicData.refSnapshotId !== previousActiveSnapshotId,
  );

  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, decrypted, "remote");

  let appliedCanonicalResult: { hasMergedLocalChanges: boolean } = {
    hasMergedLocalChanges: false,
  };
  state._applyingRemote = true;
  try {
    appliedCanonicalResult = applyCanonicalSnapshotDocToLive(
      documentId,
      state,
      serverDoc,
      "remote",
    );
  } finally {
    state._applyingRemote = false;
  }
  notifyRemoteContentReady(state, documentId);

  // Advance local keyVersion if remote uses a newer DEK
  if (snap.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = snap.publicData.keyVersion;
    checkRotationSnapshot(documentId, state);
  }

  state.activeSnapshotId = snap.publicData.snapshotId;
  state.snapshotCiphertextHash = remoteCiphertextHash;
  state.snapshotProofHash = payload.proofChainHash;

  state.snapshotBaseClocks = { ...snap.publicData.parentSnapshotUpdateClocks };
  state.knownClocks = { ...snap.publicData.parentSnapshotUpdateClocks };
  state.confirmedClocks = { ...snap.publicData.parentSnapshotUpdateClocks };
  resetWriteSessionCountersForSnapshotBaseline(state);
  state._pendingOutOfOrderUpdates = retainedQueuedUpdates;
  state.snapshotUpdatesCount = 0;
  state.localClock = nextLocalClockForDevice(state.knownClocks, state, getLocalSigningKeyId(state));

  // Build lastSavedState from server data only (not live Y.Doc which may have local edits)
  state.lastSavedState = encodeCanonicalSyncedStateAsUpdate(serverDoc);
  serverDoc.destroy();
  if (appliedCanonicalResult.hasMergedLocalChanges) {
    markMergedLocalChangesForSync(state);
  }

  // Persist anti-rollback pin
  persistDocumentRollbackPin(documentId, state);
  rememberDocumentAdmissionCheckpoint(state, payload.snapshot);
  void state.autoSync?.prepareWriteSession();
  await drainOutOfOrderUpdates(state, documentId, getLocalSigningKeyId(state) ?? undefined);
}

async function resolveSnapshotSigningKey(
  snap: NonNullable<DocumentPayload["snapshot"]>,
  state: DocumentState,
  options: { includeHistorical?: boolean } = {},
): Promise<{ keyResult: ResolveSigningKeyResult; admissionAncestryVerified: boolean }> {
  let admissionAncestryVerified = false;
  let keyResult: ResolveSigningKeyResult = lookupCachedSigningKey(
    snap.publicData.signingKeyId,
    state,
    options,
  ) ?? { status: "not_found" };

  if (keyResult.status === "not_found") {
    try {
      await verifyDocumentOperationAdmissionAncestry({
        admission: snap.admission,
        workspaceId: state.workspaceId,
        refreshKeyDirectory: createAdmissionKeyDirectoryRefresh(state, state.documentId),
      });
      admissionAncestryVerified = true;
      const admittedKey = resolveDocumentOperationSigningKeyFromAdmission({
        admission: snap.admission,
        eventType: "document_snapshot_accepted",
        publicData: snap.publicData,
      });
      if (admittedKey) {
        state.signingKeys.set(snap.publicData.signingKeyId, admittedKey.key);
        state.signingKeyOwners.set(snap.publicData.signingKeyId, admittedKey.actorUserId);
        keyResult = {
          status: "found",
          key: admittedKey.key,
          ownerId: admittedKey.actorUserId,
        };
      }
    } catch (err) {
      throw createVerificationFailedError(
        err instanceof Error ? err.message : "Snapshot admission verification failed",
      );
    }
  }

  if (keyResult.status === "not_found") {
    keyResult = await resolveSigningKey(snap.publicData.signingKeyId, state, options);
  }

  return { keyResult, admissionAncestryVerified };
}

async function computeReceivedSnapshotProof(
  worker: ReturnType<typeof getDocumentCryptoWorker>,
  snap: NonNullable<DocumentPayload["snapshot"]>,
  snapshotAdmissionEventHash: string,
): Promise<{ ciphertextHash: string; signatureHash: string; proofChainHash: string }> {
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(base64UrlDecode(snap.ciphertext)));
  const signatureHash = base64UrlEncode(
    await worker.blake3Hash(canonicalizeStrictBytes(snap.signature as unknown as StrictJsonValue)),
  );
  const proofChainHash = computeSnapshotProofLinkHash({
    documentId: snap.publicData.docId,
    snapshotId: snap.publicData.snapshotId,
    parentSnapshotId: snap.publicData.parentSnapshotId,
    parentProofHash: snap.publicData.parentProofHash,
    ciphertextHash,
    snapshotSignatureHash: signatureHash,
    snapshotAdmissionEventHash,
  });
  return { ciphertextHash, signatureHash, proofChainHash };
}

async function verifyDocumentSnapshotSignature(
  snap: NonNullable<DocumentPayload["snapshot"]>,
  publicKeyMaterial: HybridSigningPublicKeyMaterial,
  actorUserId: string,
  worker: ReturnType<typeof getDocumentCryptoWorker>,
  workspaceId: string,
): Promise<boolean> {
  return worker.verifyDocumentSnapshotSignature({
    publicKeyMaterial,
    signature: snap.signature,
    actorUserId,
    workspaceId,
    publicData: snap.publicData,
    authorityBoundary: documentOperationAuthorityBoundary(
      snap.admission,
      "document_snapshot_accepted",
    ),
    ciphertext: snap.ciphertext,
    nonce: snap.nonce,
  });
}
