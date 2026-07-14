import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getKekResolverSession } from "@/entities/session";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { workspacesApi } from "@/shared/api/workspaces";
import { clientError } from "@/shared/lib/logger";
import type { DocumentState } from "../../model/document-state/types";
import { reencryptPendingChangesForLatestDek } from "../offline/pending-reencrypt";
import { prepareDocumentShareKeyRotation } from "@/shared/lib/crypto/share-key-rotation";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { buildDekRotationStartKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/rotation-events";
import {
  buildDekOldKeyDeletionManifestHash,
  buildDekRotationCompletionKeyDirectoryAppend,
  dekRotationCompletedEventHash,
} from "@/shared/lib/crypto/key-directory/rotation-events";
import {
  buildCurrentDeviceKeyDeletionProof,
  deletedKeySecretIdsHash,
} from "@/shared/lib/crypto/device-key-deletion-proof";
import { deleteDocumentOfflineData } from "@/shared/lib/offline/storage/store";
import { clearProseMirrorXml } from "@/shared/lib/yjs/canonical-document";
import { beginDocumentOfflineWipe } from "@/shared/lib/crypto/document-key-write-barrier";
import { quiesceDocumentStateForWipe } from "../../model/document-state/lifecycle";
import { ensureDekCached } from "./inbound-verify-decrypt";

const wipeAcknowledgements = new WeakMap<DocumentState, Promise<boolean>>();
interface PendingDocumentWipe {
  endWipe: () => void;
  wasInitialized: boolean;
}

const pendingDocumentWipes = new WeakMap<DocumentState, PendingDocumentWipe>();

/**
 * Detect needs_dek_rotation and complete rotation if needed.
 * Other workspace members with document:write and KEK access detect the flag on
 * document access and auto-complete the rotation.
 * Errors are caught silently — rotation failure must not block document viewing.
 */
export async function completeDekRotationIfNeeded(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  try {
    await doCompleteDekRotation(documentId, workspaceId, state);
  } catch (err) {
    clientError("dek_rotation_completion_failed", { documentId, workspaceId, error: err });
    // Another client may have completed the rotation. Refresh active DEK version.
    try {
      const worker = getCryptoWorker();
      const refreshed = await encryptionApi.getDocumentKeys(documentId);
      const refreshedActive = refreshed.keys.find((key) => key.is_active);
      if (refreshedActive && refreshedActive.key_version !== state.keyVersion) {
        await resolveKekByVersion(
          workspaceId,
          refreshedActive.kek_version,
          getKekResolverSession(),
        );
        await worker.unwrapDek({
          encryptedDek: base64UrlDecode(refreshedActive.encrypted_dek),
          nonce: base64UrlDecode(refreshedActive.nonce),
          documentId,
          workspaceId,
          keyVersion: refreshedActive.key_version,
          isActive: true,
          kekVersion: refreshedActive.kek_version,
        });
        state.keyVersion = refreshedActive.key_version;
      }
    } catch {
      // Best-effort refresh
    }
  }
}

export async function completeDekRotationNow(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  await doCompleteDekRotation(documentId, workspaceId, state);
}

export async function acknowledgeDocumentWipeIfRequired(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<boolean> {
  const existing = wipeAcknowledgements.get(state);
  if (existing) return existing;
  const acknowledgement = doAcknowledgeDocumentWipeIfRequired(documentId, workspaceId, state);
  wipeAcknowledgements.set(state, acknowledgement);
  try {
    return await acknowledgement;
  } finally {
    if (wipeAcknowledgements.get(state) === acknowledgement) {
      wipeAcknowledgements.delete(state);
    }
  }
}

async function doAcknowledgeDocumentWipeIfRequired(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<boolean> {
  let requirement = await encryptionApi.getDocumentWipeRequirement(documentId);
  let pendingWipe = pendingDocumentWipes.get(state);
  if (!requirement) {
    if (!pendingWipe) return false;
    await finishDocumentWipe(documentId, workspaceId, state, pendingWipe);
    return true;
  }
  const session = getKekResolverSession();
  const userId = session.auth?.user.id;
  const deviceId = session.device?.deviceId;
  if (!userId || !deviceId) throw new Error("document_wipe_actor_unavailable");

  if (!pendingWipe) {
    const wasInitialized = state.initialized;
    await quiesceDocumentStateForWipe(state, true);
    const endWipe = await beginDocumentOfflineWipe(documentId);
    pendingWipe = { endWipe, wasInitialized };
    pendingDocumentWipes.set(state, pendingWipe);
  }

  while (requirement) {
    if (requirement.workspace_id !== workspaceId) {
      throw new Error("document_wipe_workspace_mismatch");
    }
    const directory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      rrpDeviceId: deviceId,
    });
    await getCryptoWorker().evictDek(documentId, requirement.old_key_version);
    await deleteDocumentOfflineData(documentId);
    state.yDoc.transact(() => {
      const text = state.yDoc.getText("content");
      if (text.length > 0) text.delete(0, text.length);
    }, "dek-wipe");
    clearProseMirrorXml(state.yDoc, "dek-wipe");
    state.lastSavedState = null;
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    state.loadedFromOfflineCache = false;

    const proof = await buildCurrentDeviceKeyDeletionProof({
      workspaceId,
      userId,
      deviceId,
      rotationKind: "dek",
      scopeKind: "document",
      scopeId: documentId,
      oldKeyVersion: requirement.old_key_version,
      rotationCompletedEventHash: requirement.rotation_completed_event_hash,
      deletedSecretIdsHash: requirement.deleted_secret_ids_hash,
      checkpointEnvelope: directory.checkpoint,
    });

    await encryptionApi.acknowledgeDocumentWipe(documentId, {
      device_key_deletion_proof: proof as never,
    });
    requirement = await encryptionApi.getDocumentWipeRequirement(documentId);
  }

  await finishDocumentWipe(documentId, workspaceId, state, pendingWipe);
  return true;
}

async function finishDocumentWipe(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  pendingWipe: PendingDocumentWipe,
): Promise<void> {
  // The wipe is durable once the server accepts the deletion proof. Release the
  // offline-write barrier so initialization can cache the replacement DEK.
  pendingWipe.endWipe();
  if (pendingDocumentWipes.get(state) === pendingWipe) pendingDocumentWipes.delete(state);

  if (pendingWipe.wasInitialized) {
    state.initialized = false;
    state.error = null;
    const { initializeDocumentSync } = await import("./initialize");
    const reinitialize = initializeDocumentSync(documentId, workspaceId, state, {
      skipDocumentWipeAcknowledgement: true,
    });
    state.initPromise = reinitialize;
    try {
      await reinitialize;
    } finally {
      if (state.initPromise === reinitialize) state.initPromise = null;
    }
  }

  state._reconnecting = false;
  state._syncPaused = false;
}

async function doCompleteDekRotation(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const doc = await documentsApi.get(documentId);
  if (doc?.needs_rotation_snapshot) {
    await preparePendingRotationSnapshot(documentId, workspaceId, state, doc);
    return;
  }
  if (!doc || !documentDekRotationRequired(doc)) return;

  // KEK rotation must complete before DEK rotation is attempted.
  const workspace = await workspacesApi.get(workspaceId);
  if (workspace.needs_kek_rotation) return;

  // Re-resolve active KEK (may have changed since init if KEK rotation just completed)
  await resolveActiveKek(workspaceId, getKekResolverSession());

  const worker = getCryptoWorker();
  const session = getKekResolverSession();
  const actorUserId = session.auth?.user.id;
  const actorDeviceId = session.device?.deviceId;
  if (!actorUserId || !actorDeviceId) throw new Error("dek_rotation_actor_unavailable");
  if (!doc.dek_rotation_reason) throw new Error("dek_rotation_reason_unavailable");
  await ensureDekCached(documentId, workspaceId, state.keyVersion, state);
  const nextKeyVersion = state.keyVersion + 1;

  // Generate new DEK without setting it as active (setActive: false).
  // Active version is only updated after successful server save.
  const {
    encryptedDek,
    nonce,
    keyVersion: kekVersion,
  } = await worker.generateDek(documentId, workspaceId, nextKeyVersion, false);

  // Save to server (also clears needs_dek_rotation flag and updates min_dek_version)
  try {
    const startDirectory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      rrpDeviceId: actorDeviceId,
    });
    const startAppend = await buildDekRotationStartKeyDirectoryAppend({
      workspaceId,
      documentId,
      actorUserId,
      actorDeviceId,
      checkpointEnvelope: startDirectory.checkpoint,
      oldKeyVersion: state.keyVersion,
      newKeyVersion: nextKeyVersion,
      reason: doc.dek_rotation_reason,
    });
    const shareRotation = await prepareDocumentShareKeyRotation({
      documentId,
      workspaceId,
      nextKeyVersion,
      actorUserId,
      actorDeviceId,
      checkpointEnvelope: startAppend.checkpoint,
    });
    await encryptionApi.createDocumentKey(documentId, {
      encrypted_dek: base64UrlEncode(encryptedDek),
      nonce: base64UrlEncode(nonce),
      key_version: nextKeyVersion,
      kek_version: kekVersion,
      dek_rotation_start_events: startAppend.events,
      dek_rotation_start_checkpoint: startAppend.checkpoint,
      ...shareRotation,
    });
    await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      rrpDeviceId: actorDeviceId,
    });
  } catch (err) {
    // POST failed: evict the speculative DEK from cache
    await worker.evictDek(documentId, nextKeyVersion).catch(() => {
      // Failed cache eviction is harmless because the server never accepted this speculative DEK.
    });
    throw err;
  }

  // POST succeeded: now activate the new DEK
  await worker.unwrapDek({
    encryptedDek,
    nonce,
    documentId,
    workspaceId,
    keyVersion: nextKeyVersion,
    isActive: true,
    kekVersion,
  });

  await reencryptPendingChangesForLatestDek({
    documentId,
    latestKeyVersion: nextKeyVersion,
    worker,
  });

  // Don't advance state.keyVersion yet — peers still have the old DEK.
  // The rotation snapshot is the cutover point; keyVersion advances in handleSnapshotSaved.
  // Ephemeral messages continue using the old DEK until all peers have the new one.
  state.pendingRotationKeyVersion = nextKeyVersion;

  await reEncryptTitleIfNeeded(documentId, workspaceId, state, nextKeyVersion);

  // Set snapshot trigger (post-rotation snapshot requirement)
  state.pendingRotationSnapshot = true;
  state.autoSync?.notifyLocalEdit();
}

async function preparePendingRotationSnapshot(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  doc: Awaited<ReturnType<typeof documentsApi.get>>,
): Promise<void> {
  const targetKeyVersion = doc.min_dek_version;
  const titleKeyVersion = doc.encrypted_title_key_version;
  if (
    doc.encrypted_title &&
    typeof titleKeyVersion === "number" &&
    titleKeyVersion < targetKeyVersion
  ) {
    await ensureDekCached(documentId, workspaceId, titleKeyVersion, state);
    await reEncryptTitleIfNeeded(documentId, workspaceId, state, targetKeyVersion, doc);
  }
  if (state.keyVersion < targetKeyVersion) {
    state.pendingRotationKeyVersion = targetKeyVersion;
  }
  state.pendingRotationSnapshot = true;
  state.autoSync?.notifyLocalEdit();
}

/**
 * Re-encrypt document title if its key version doesn't match the active DEK.
 * Executed immediately after DEK rotation (not deferred to Snapshot).
 * Also handles crash recovery: stale title detected on document open.
 */
export async function reEncryptTitleIfNeeded(
  documentId: string,
  _workspaceId: string,
  state: DocumentState,
  targetKeyVersion?: number,
  docMeta?: Awaited<ReturnType<typeof documentsApi.get>>,
): Promise<void> {
  const worker = getCryptoWorker();
  const newKeyVersion = targetKeyVersion ?? state.keyVersion;

  const doc = docMeta ?? (await documentsApi.get(documentId));

  if (!doc.encrypted_title || !doc.encrypted_title_nonce || !doc.encrypted_title_key_version) {
    return;
  }

  // Only re-encrypt if title is on an older DEK version
  if (doc.encrypted_title_key_version >= newKeyVersion) return;

  const oldKeyVersion = doc.encrypted_title_key_version;
  const title = await worker.decryptTitle({
    encrypted: base64UrlDecode(doc.encrypted_title),
    nonce: base64UrlDecode(doc.encrypted_title_nonce),
    documentId,
    keyVersion: oldKeyVersion,
  });

  const { encrypted, nonce } = await worker.encryptTitle({
    title,
    documentId,
    keyVersion: newKeyVersion,
  });

  await documentsApi.update(documentId, {
    encrypted_title: base64UrlEncode(encrypted),
    encrypted_title_nonce: base64UrlEncode(nonce),
    encrypted_title_key_version: newKeyVersion,
  });
}

export async function completeDekRotationAfterSnapshot(params: {
  documentId: string;
  workspaceId: string;
  oldKeyVersion: number;
  newKeyVersion: number;
  state: DocumentState;
}): Promise<void> {
  const session = getKekResolverSession();
  const actorUserId = session.auth?.user.id;
  const actorDeviceId = session.device?.deviceId;
  if (!actorUserId || !actorDeviceId) throw new Error("dek_rotation_actor_unavailable");

  const directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    rrpDeviceId: actorDeviceId,
  });
  const materials = await encryptionApi.prepareDekRotationCompletion(
    params.documentId,
    params.newKeyVersion,
  );
  if (
    materials.old_key_version !== params.oldKeyVersion ||
    materials.new_key_version !== params.newKeyVersion
  ) {
    throw new Error("dek_rotation_manifest_version_mismatch");
  }

  const completedEventHash = dekRotationCompletedEventHash({
    workspaceId: params.workspaceId,
    documentId: params.documentId,
    actorUserId,
    actorDeviceId,
    checkpointEnvelope: directory.checkpoint,
    oldKeyVersion: params.oldKeyVersion,
    newKeyVersion: params.newKeyVersion,
    completionManifestHash: materials.completion_manifest_hash,
  });

  const deletedSecretIdsHash = deletedKeySecretIdsHash(
    `document:dek:${params.documentId}:${params.oldKeyVersion}`,
  );
  const wipeRequiredDeviceIds = await workspaceActiveDeviceIds(params.workspaceId);
  const deletionManifestHash = buildDekOldKeyDeletionManifestHash({
    documentId: params.documentId,
    oldKeyVersion: params.oldKeyVersion,
    rotationCompletedEventHash: completedEventHash,
    deletedSecretIdsHash,
    deletedWrapIdsHash: materials.deleted_wrap_ids_hash,
    deviceKeyDeletionProofs: [],
    wipeRequiredDeviceIds,
    serverRejectsOldKeyUploadsAfterSequence:
      materials.server_rejects_old_key_uploads_after_sequence,
  });
  const append = await buildDekRotationCompletionKeyDirectoryAppend({
    workspaceId: params.workspaceId,
    documentId: params.documentId,
    actorUserId,
    actorDeviceId,
    checkpointEnvelope: directory.checkpoint,
    oldKeyVersion: params.oldKeyVersion,
    newKeyVersion: params.newKeyVersion,
    completionManifestHash: materials.completion_manifest_hash,
    deletionManifestHash,
  });

  await encryptionApi.completeDekRotation(params.documentId, {
    new_key_version: params.newKeyVersion,
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
    device_key_deletion_proofs: [],
    wipe_required_device_ids: wipeRequiredDeviceIds,
  });
  await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    rrpDeviceId: actorDeviceId,
  });
  params.state._syncPaused = true;
  queueMicrotask(() => {
    void acknowledgeDocumentWipeIfRequired(
      params.documentId,
      params.workspaceId,
      params.state,
    ).catch((error) => {
      clientError("dek_rotation_initiator_wipe_failed", {
        documentId: params.documentId,
        workspaceId: params.workspaceId,
        error,
      });
    });
  });
}

async function workspaceActiveDeviceIds(workspaceId: string): Promise<string[]> {
  const { members } = await workspacesApi.listMembers(workspaceId);
  const ids = await Promise.all(
    members.map(async (member) => {
      const response = await workspacesApi.listMemberDevices(workspaceId, member.user_id, false);
      return response.devices.map((device) => device.device_id);
    }),
  );
  return [...new Set(ids.flat())].sort((left, right) => left.localeCompare(right));
}

function documentDekRotationRequired(doc: {
  needs_dek_rotation: boolean;
  dek_rotation_due_at?: string | null;
}): boolean {
  if (doc.needs_dek_rotation) return true;
  if (!doc.dek_rotation_due_at) return false;

  const dueAt = Date.parse(doc.dek_rotation_due_at);
  return Number.isFinite(dueAt) && dueAt <= Date.now();
}
