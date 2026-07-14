import {
  authState,
  cryptoWorkerReady,
  deviceState,
  getKekResolverSession,
  setAuthState,
} from "@/entities/session";
import { devicesApi, encryptionApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  buildIdentityRetirementKeyDirectoryAppend,
  buildIdentityRotationKeyDirectoryAppend,
  identityDeletionManifest,
  identityDeletionManifestHash,
  identityRevokedOldIdentityPublicKeyEventHash,
  identityRotationCompletedEventHash,
} from "@/shared/lib/crypto/key-directory/identity-rotation-events";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { persistWorkspaceKekForMember } from "@/shared/lib/crypto/workspace-kek-persistence";
import { ensureWorkspaceIdentityKey } from "@/shared/lib/crypto/workspace-identity-directory";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  lookupVerifiedKeyDirectoryCheckpointBodies,
  lookupVerifiedKeyDirectoryEventBodies,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";

type RotationStatus = Awaited<ReturnType<typeof encryptionApi.getIdentityRotationStatus>>;
type SuccessorMaterial = Awaited<
  ReturnType<ReturnType<typeof getCryptoWorker>["generateIdentitySuccessor"]>
>;

export async function rotateCurrentUserIdentity(): Promise<RotationStatus> {
  const auth = authState();
  const device = deviceState();
  if (!cryptoWorkerReady() || !auth || !device?.deviceId) {
    throw new Error("identity_rotation_session_unavailable");
  }
  const worker = getCryptoWorker();
  let status = await encryptionApi.getIdentityRotationStatus({ rrpDeviceId: device.deviceId });
  await worker.setIdentityRotationDeadline(status.rotation_due_at);
  let successor: SuccessorMaterial;

  if (status.pending_key_version) {
    successor = await restorePendingSuccessor(status, status.finalization_started);
  } else {
    successor = await worker.generateIdentitySuccessor();
    const userDirectory = await fetchVerifiedKeyDirectory({
      scopeKind: "user",
      scopeId: auth.user.id,
      rrpDeviceId: device.deviceId,
    });
    await trustVerifiedIdentityCheckpoint(worker, auth.user.id, userDirectory.checkpoint.payload);
    const append = await buildIdentityRotationKeyDirectoryAppend({
      userId: auth.user.id,
      checkpointEnvelope: userDirectory.checkpoint,
      successorHybridEncryptionPublicKeyMaterial: successor.hybridEncryptionPublicKeyMaterial,
      successorHybridSigningPublicKeyMaterial: successor.hybridSigningPublicKeyMaterial,
      oldKeyVersion: status.current_key_version!,
      newKeyVersion: (status.current_key_version ?? 0) + 1,
    });
    const encrypted = await worker.wrapIdentitySuccessorForServer(auth.user.id);
    try {
      status = await encryptionApi.prepareIdentityRotation(
        {
          hybrid_encryption_public_key_material: successor.hybridEncryptionPublicKeyMaterial,
          hybrid_signing_public_key_material: successor.hybridSigningPublicKeyMaterial,
          encrypted_identity_hybrid_encryption_private_key_material: base64UrlEncode(
            encrypted.encryptedHybridEncryptionPrivateKeyMaterial,
          ),
          identity_hybrid_encryption_private_key_material_nonce: base64UrlEncode(
            encrypted.hybridEncryptionPrivateKeyMaterialNonce,
          ),
          encrypted_identity_hybrid_signing_private_key_material: base64UrlEncode(
            encrypted.encryptedHybridSigningPrivateKeyMaterial,
          ),
          identity_hybrid_signing_private_key_material_nonce: base64UrlEncode(
            encrypted.hybridSigningPrivateKeyMaterialNonce,
          ),
          user_key_directory_events: append.events,
          user_key_directory_checkpoint: append.checkpoint,
        },
        { rrpDeviceId: device.deviceId },
      );
    } catch (error) {
      if (!(error instanceof ApiError) || error.code !== "identity_rotation_already_pending") {
        throw error;
      }
      status = await encryptionApi.getIdentityRotationStatus({ rrpDeviceId: device.deviceId });
      if (!status.pending_key_version) throw error;
      successor = await restorePendingSuccessor(status, status.finalization_started);
    }
  }

  if (
    !status.current_encryption_key_id ||
    !status.current_signing_key_id ||
    !status.pending_signing_key_id
  ) {
    throw new Error("identity_rotation_key_ids_incomplete");
  }
  const currentEncryptionKeyId = status.current_encryption_key_id;
  const currentSigningKeyId = status.current_signing_key_id;
  const pendingSigningKeyId = status.pending_signing_key_id;
  const coveredWorkspaceIds = new Set(status.workspace_rewraps.map((entry) => entry.workspace_id));
  for (const target of status.required_workspace_targets) {
    if (coveredWorkspaceIds.has(target.workspace_id)) continue;
    const workspaceId = target.workspace_id;
    const { kekVersion } = await resolveActiveKek(workspaceId, getKekResolverSession());
    if (kekVersion !== target.key_version) {
      throw new Error("identity_rotation_workspace_key_version_mismatch");
    }
    const directory = await ensureWorkspaceIdentityKey({
      workspaceId,
      ownerUserId: auth.user.id,
      ownerDeviceId: device.deviceId,
      targetUserId: auth.user.id,
      targetIdentityHybridEncryptionPublicKeyMaterial: successor.hybridEncryptionPublicKeyMaterial,
      targetIdentityHybridSigningPublicKeyMaterial: successor.hybridSigningPublicKeyMaterial,
    });
    await persistWorkspaceKekForMember({
      workspaceId,
      userId: auth.user.id,
      senderDeviceId: device.deviceId,
      targetUserId: auth.user.id,
      targetIdentityHybridEncryptionPublicKeyMaterial: successor.hybridEncryptionPublicKeyMaterial,
      keyVersion: target.key_version,
      rrpDeviceId: device.deviceId,
      keyDirectoryCheckpoint: directory.checkpoint,
      ignoreConflict: true,
    });
  }

  status = await encryptionApi.getIdentityRotationStatus({ rrpDeviceId: device.deviceId });
  await worker.setIdentityRotationDeadline(status.rotation_due_at);
  if (!status.envelopes_complete || !status.pending_key_version) {
    throw new Error("identity_rotation_envelopes_incomplete");
  }

  const authorization = await worker.beginIdentitySuccessorFinalization();
  const rotationDirectory = await fetchVerifiedKeyDirectory({
    scopeKind: "user",
    scopeId: auth.user.id,
    rrpDeviceId: device.deviceId,
  });
  const rotationCheckpointPayload = rotationDirectory.checkpoint.payload as Record<string, unknown>;
  const newUserCheckpointHash = blake3Base64Url(
    canonicalizeStrictBytes(rotationCheckpointPayload as StrictJsonValue),
  );
  const oldUserCheckpointHash = rotationCheckpointPayload.previous_checkpoint_hash;
  if (typeof oldUserCheckpointHash !== "string") {
    throw new Error("identity_rotation_previous_checkpoint_missing");
  }
  const startedEvent = lookupVerifiedKeyDirectoryEventBodies("user", auth.user.id).find(
    (event) =>
      event.payload.event_type === "rotation_started" &&
      (event.payload.body as Record<string, unknown>).new_identity_signing_key_id ===
        pendingSigningKeyId,
  );
  if (!startedEvent) throw new Error("identity_rotation_started_event_missing");
  const startedEventHash = blake3Base64Url(
    canonicalizeStrictBytes(startedEvent.payload as StrictJsonValue),
  );
  const sortedWorkspaceRewraps = [...status.workspace_rewraps].sort((a, b) =>
    a.workspace_id.localeCompare(b.workspace_id),
  );
  const workspaceRewrapsHash = blake3Base64Url(
    canonicalizeStrictBytes({ workspace_rewraps: sortedWorkspaceRewraps }),
  );
  const completionManifest = {
    protocol: "refmd.identity-rotation-completion-manifest",
    version: 1,
    rotation_kind: "identity",
    scope_kind: "user",
    scope_id: auth.user.id,
    old_identity_signing_key_id: currentSigningKeyId,
    old_identity_encryption_key_id: currentEncryptionKeyId,
    new_identity_signing_key_id: authorization.successorSigningKeyId,
    new_identity_encryption_key_id: authorization.successorEncryptionKeyId,
    started_event_hash: startedEventHash,
    old_user_checkpoint_hash: oldUserCheckpointHash,
    new_user_checkpoint_hash: newUserCheckpointHash,
    new_user_checkpoint_sequence: rotationCheckpointPayload.sequence as number,
    old_identity_checkpoint_signature_hash: checkpointSignatureHash(
      rotationDirectory.checkpoint.signatures,
      currentSigningKeyId,
    ),
    new_identity_checkpoint_signature_hash: checkpointSignatureHash(
      rotationDirectory.checkpoint.signatures,
      pendingSigningKeyId,
    ),
    workspace_rewraps: sortedWorkspaceRewraps,
    workspace_rewraps_hash: workspaceRewrapsHash,
    revoked_old_identity_public_key_event_hash: identityRevokedOldIdentityPublicKeyEventHash({
      userId: auth.user.id,
      checkpointEnvelope: rotationDirectory.checkpoint,
      successorSigningKeyId: pendingSigningKeyId,
    }),
    semantic_state_proof_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        old_user_checkpoint_hash: oldUserCheckpointHash,
        new_user_checkpoint_hash: newUserCheckpointHash,
        workspace_rewraps_hash: workspaceRewrapsHash,
      }),
    ),
  } as const;
  const completionManifestHash = blake3Base64Url(canonicalizeStrictBytes(completionManifest));
  const rotationCompletedEventHash = identityRotationCompletedEventHash({
    userId: auth.user.id,
    checkpointEnvelope: rotationDirectory.checkpoint,
    successorSigningKeyId: pendingSigningKeyId,
    oldKeyVersion: status.current_key_version!,
    newKeyVersion: status.pending_key_version,
    completionManifestHash,
  });
  await encryptionApi.activateIdentityRotation(
    { key_version: status.pending_key_version },
    { rrpDeviceId: device.deviceId },
  );
  const activation = await worker.activateIdentitySuccessor();
  if (!activation.oldPrivateKeyDeleted) throw new Error("identity_old_private_key_deletion_failed");
  const signedDeviceProof = await worker.signDeviceKeyDeletionProof({
    payload: {
      protocol: "refmd.identity-key-deletion-proof",
      version: 1,
      user_id: auth.user.id,
      device_id: device.deviceId,
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: auth.user.id,
      old_identity_signing_key_id: authorization.previousSigningKeyId,
      old_identity_encryption_key_id: authorization.previousEncryptionKeyId,
      new_identity_signing_key_id: authorization.successorSigningKeyId,
      new_identity_encryption_key_id: authorization.successorEncryptionKeyId,
      old_user_checkpoint_hash: oldUserCheckpointHash,
      new_user_checkpoint_hash: newUserCheckpointHash,
      rotation_completed_event_hash: rotationCompletedEventHash,
      deleted_identity_secret_ids_hash: blake3Base64Url(
        canonicalizeStrictBytes({
          key_ids: [
            authorization.previousEncryptionKeyId,
            authorization.previousSigningKeyId,
          ].sort(),
        }),
      ),
      deleted_storage_classes: [
        "crypto_worker_state",
        "indexeddb_cache",
        "local_encrypted_key_store",
      ],
      local_cache_epoch: 1,
      proof_nonce: base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))),
    },
    actor: {
      signer_kind: "device",
      user_id: auth.user.id,
      device_id: device.deviceId,
      signing_key_id: device.deviceSigningKeyId,
      key_scope_kind: "user",
      key_scope_id: auth.user.id,
      key_checkpoint_sequence: rotationDirectory.checkpoint.payload.sequence,
      key_checkpoint_hash: blake3Base64Url(
        canonicalizeStrictBytes(rotationDirectory.checkpoint.payload as StrictJsonValue),
      ),
    },
  });
  const deviceProof = {
    payload: signedDeviceProof.payload,
    transcript: signedDeviceProof.transcript,
    signature: signedDeviceProof.signature,
  };
  const { devices } = await devicesApi.list({ rrpDeviceId: device.deviceId });
  const wipeRequiredDeviceIds = devices
    .filter((entry) => entry.id !== device.deviceId)
    .map((entry) => entry.id);
  const deletedIdentitySecretIdsHash = deviceProof.payload
    .deleted_identity_secret_ids_hash as string;
  const deletionManifestInput = {
    userId: auth.user.id,
    oldIdentitySigningKeyId: currentSigningKeyId,
    oldIdentityEncryptionKeyId: currentEncryptionKeyId,
    newIdentitySigningKeyId: pendingSigningKeyId,
    deletedIdentitySecretIdsHash,
    rotationCompletedEventHash,
    deviceKeyDeletionProofs: [deviceProof],
    wipeRequiredDeviceIds,
    serverRejectsOldIdentityAfterSequence:
      (rotationCheckpointPayload.covered_event_head as Record<string, number>).head_sequence + 4,
  };
  const deletionManifest = identityDeletionManifest(deletionManifestInput);
  const deletionManifestHash = identityDeletionManifestHash(deletionManifestInput);
  const retirement = await buildIdentityRetirementKeyDirectoryAppend({
    userId: auth.user.id,
    checkpointEnvelope: rotationDirectory.checkpoint,
    successorSigningKeyId: pendingSigningKeyId,
    oldSigningKeyId: currentSigningKeyId,
    oldEncryptionKeyId: currentEncryptionKeyId,
    oldKeyVersion: status.current_key_version!,
    newKeyVersion: status.pending_key_version,
    completionManifestHash,
    deletionManifestHash,
  });
  const finalized = await retryFinalize(
    {
      key_version: status.pending_key_version,
      deletion_proof: {
        old_encryption_key_id: authorization.previousEncryptionKeyId,
        old_private_key_use_blocked: true,
        old_signing_key_id: authorization.previousSigningKeyId,
        old_version: status.current_key_version!,
        persistent_identity_deletion_authorized: true,
        successor_encryption_key_id: authorization.successorEncryptionKeyId,
        successor_signing_key_id: authorization.successorSigningKeyId,
        successor_version: status.pending_key_version,
        rotation_completed_event_hash: rotationCompletedEventHash,
        completion_manifest_hash: completionManifestHash,
        deletion_manifest_hash: deletionManifestHash,
        completion_manifest: completionManifest,
        deletion_manifest: deletionManifest,
        device_key_deletion_proofs: [deviceProof as never],
        wipe_required_device_ids: wipeRequiredDeviceIds,
      },
      user_key_directory_events: retirement.events,
      user_key_directory_checkpoint: retirement.checkpoint,
    },
    device.deviceId,
    {
      keyVersion: status.pending_key_version,
      encryptionKeyId: authorization.successorEncryptionKeyId,
      signingKeyId: authorization.successorSigningKeyId,
    },
  );
  const finalDirectory = await fetchVerifiedKeyDirectory({
    scopeKind: "user",
    scopeId: auth.user.id,
    rrpDeviceId: device.deviceId,
  });
  await trustVerifiedIdentityCheckpoint(worker, auth.user.id, finalDirectory.checkpoint.payload);
  setAuthState({
    ...auth,
    identityEcdhPublic: successor.ecdhPublic,
    identityHybridSigningPublicKeyMaterial: successor.hybridSigningPublicKeyMaterial,
  });
  return finalized;
}

async function trustVerifiedIdentityCheckpoint(
  worker: ReturnType<typeof getCryptoWorker>,
  userId: string,
  checkpointPayload: Record<string, unknown>,
): Promise<void> {
  await worker.trustIdentityRotationCheckpoint({
    checkpointPayload,
    checkpointAncestryPayloads: lookupVerifiedKeyDirectoryCheckpointBodies("user", userId).map(
      (entry) => entry.payload,
    ),
  });
}

function checkpointSignatureHash(
  signatures: Array<Record<string, unknown>>,
  signingKeyId: string,
): string {
  const signature = signatures.find((entry) => {
    const signer = entry.signer as Record<string, unknown> | undefined;
    return signer?.signing_key_id === signingKeyId;
  });
  if (!signature) throw new Error("identity_rotation_checkpoint_signature_missing");
  return blake3Base64Url(canonicalizeStrictBytes(signature as StrictJsonValue));
}

async function restorePendingSuccessor(
  status: RotationStatus,
  finalizationStarted: boolean,
): Promise<SuccessorMaterial> {
  const encryptedEncryption =
    status.pending_encrypted_identity_hybrid_encryption_private_key_material;
  const encryptionNonce = status.pending_identity_hybrid_encryption_private_key_material_nonce;
  const encryptedSigning = status.pending_encrypted_identity_hybrid_signing_private_key_material;
  const signingNonce = status.pending_identity_hybrid_signing_private_key_material_nonce;
  if (
    !encryptedEncryption ||
    !encryptionNonce ||
    !encryptedSigning ||
    !signingNonce ||
    !status.pending_encryption_key_id ||
    !status.pending_signing_key_id
  ) {
    throw new Error("identity_rotation_pending_material_incomplete");
  }
  const encrypted = {
    encryptedHybridEncryptionPrivateKeyMaterial: base64UrlDecode(encryptedEncryption),
    hybridEncryptionPrivateKeyMaterialNonce: base64UrlDecode(encryptionNonce),
    encryptionKeyId: status.pending_encryption_key_id,
    encryptedHybridSigningPrivateKeyMaterial: base64UrlDecode(encryptedSigning),
    hybridSigningPrivateKeyMaterialNonce: base64UrlDecode(signingNonce),
    signingKeyId: status.pending_signing_key_id,
  };
  if (finalizationStarted) {
    if (!status.current_encryption_key_id || !status.current_signing_key_id) {
      throw new Error("identity_rotation_previous_key_ids_incomplete");
    }
    return getCryptoWorker().restoreActivatedIdentitySuccessor({
      ...encrypted,
      previousEncryptionKeyId: status.current_encryption_key_id,
      previousSigningKeyId: status.current_signing_key_id,
    });
  }
  return getCryptoWorker().importIdentitySuccessor(encrypted);
}

async function retryFinalize(
  body: Parameters<typeof encryptionApi.finalizeIdentityRotation>[0],
  deviceId: string,
  expected: { keyVersion: number; encryptionKeyId: string; signingKeyId: string },
): Promise<RotationStatus> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const status = await encryptionApi.finalizeIdentityRotation(body, { rrpDeviceId: deviceId });
      if (identityRotationCommitted(status, expected)) return status;
      throw new Error("identity_rotation_finalize_confirmation_invalid");
    } catch (error) {
      lastError = error;
      const status = await encryptionApi
        .getIdentityRotationStatus({ rrpDeviceId: deviceId })
        .catch(() => null);
      if (status && identityRotationCommitted(status, expected)) {
        return status;
      }
      await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt));
    }
  }
  throw lastError;
}

function identityRotationCommitted(
  status: RotationStatus,
  expected: { keyVersion: number; encryptionKeyId: string; signingKeyId: string },
): boolean {
  return (
    status.current_key_version === expected.keyVersion &&
    status.current_encryption_key_id === expected.encryptionKeyId &&
    status.current_signing_key_id === expected.signingKeyId &&
    status.pending_key_version === null
  );
}
