import { blake3Base64Url } from "./hash";
import { decodeBase64UrlStrict } from "./encoding";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getActiveSigningSurface } from "./signing-surface";
import { CURRENT_PROTOCOL_VERSION } from "./suite";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";
import { numberValue, stringValue, transcriptBase } from "./signature-transcript-core";

export function buildRecoveryDeviceApprovalTranscript(params: {
  ownerId: string;
  approvingSigningKeyId: string;
  approvingKeyCheckpointSequence: number;
  approvingKeyCheckpointHash: string;
  pendingRegistrationId: string;
  pendingRegistrationChallengeHash: string;
  recoverySessionTranscriptHash: string;
  recoveryCapabilityHash: string;
  pendingRegistrationBindingHash: string;
  approvedDeviceId: string;
  approvedDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  approvedDeviceEcdhPublicKey: string;
  approvedDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  clientNonce: string;
  targetKeyCheckpointSequence: number;
  targetKeyCheckpointHash: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("recovery_device_approval", "none");
  const encryptionKeyId = computeHybridEncryptionKeyId(
    params.approvedDeviceHybridEncryptionPublicKeyMaterial,
  );
  const targetDeviceHybridSigningPublicKeyMaterialHash = blake3Base64Url(
    canonicalizeStrictBytes(
      params.approvedDeviceHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
    ),
  );
  const targetDeviceHybridEncryptionPublicKeyMaterialHash = blake3Base64Url(
    canonicalizeStrictBytes(
      params.approvedDeviceHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
    ),
  );
  const targetDeviceClientNonceHash = blake3Base64Url(
    decodeBase64UrlStrict(params.clientNonce, 16),
  );
  const targetDeviceSigningKeyId = blake3Base64Url(
    canonicalizeStrictBytes(
      params.approvedDeviceHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
    ),
  );
  const subject = {
    approval_signature_surface: "recovery_device_approval",
    pending_registration_id: params.pendingRegistrationId,
    pending_registration_challenge_hash: params.pendingRegistrationChallengeHash,
    approving_owner_kind: "identity",
    approving_owner_id: params.ownerId,
    approving_signing_key_id: params.approvingSigningKeyId,
    approving_key_checkpoint_sequence: params.approvingKeyCheckpointSequence,
    approving_key_checkpoint_hash: params.approvingKeyCheckpointHash,
    target_device_id: params.approvedDeviceId,
    target_device_signing_key_id: targetDeviceSigningKeyId,
    target_device_hybrid_signing_public_key_material_hash:
      targetDeviceHybridSigningPublicKeyMaterialHash,
    target_device_hybrid_encryption_public_key_material_hash:
      targetDeviceHybridEncryptionPublicKeyMaterialHash,
    target_device_encryption_key_id: encryptionKeyId,
    target_device_client_nonce_hash: targetDeviceClientNonceHash,
    target_key_checkpoint_sequence: params.targetKeyCheckpointSequence,
    target_key_checkpoint_hash: params.targetKeyCheckpointHash,
    recovery_session_transcript_hash: params.recoverySessionTranscriptHash,
    recovery_capability_hash: params.recoveryCapabilityHash,
    pending_registration_binding_hash: params.pendingRegistrationBindingHash,
  } as const;

  return transcriptBase("recovery_device_approval", surface, "identity", params.ownerId, {
    ...subject,
  });
}

export function buildPendingRegistrationBindingHash(params: {
  userId: string;
  pendingRegistrationId: string;
  pendingRegistrationChallengeHash: string;
  targetDeviceId: string;
  targetDeviceSigningKeyId: string;
  targetDeviceHybridSigningPublicKeyMaterial: unknown;
  targetDeviceHybridEncryptionPublicKeyMaterial: unknown;
  targetDeviceEncryptionKeyId: string;
  targetDeviceClientNonce: string;
  targetKeyCheckpointSequence: number;
  targetKeyCheckpointHash: string;
}): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.pending-registration-binding",
      version: 1,
      user_id: params.userId,
      pending_registration_id: params.pendingRegistrationId,
      pending_registration_challenge_hash: params.pendingRegistrationChallengeHash,
      target_device_id: params.targetDeviceId,
      target_device_signing_key_id: params.targetDeviceSigningKeyId,
      target_device_hybrid_signing_public_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          params.targetDeviceHybridSigningPublicKeyMaterial as StrictJsonValue,
        ),
      ),
      target_device_hybrid_encryption_public_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          params.targetDeviceHybridEncryptionPublicKeyMaterial as StrictJsonValue,
        ),
      ),
      target_device_encryption_key_id: params.targetDeviceEncryptionKeyId,
      target_device_client_nonce_hash: blake3Base64Url(
        decodeBase64UrlStrict(params.targetDeviceClientNonce, 16),
      ),
      target_key_checkpoint_sequence: params.targetKeyCheckpointSequence,
      target_key_checkpoint_hash: params.targetKeyCheckpointHash,
    } as unknown as StrictJsonValue),
  );
}

export function buildRecoverySessionTranscript(params: {
  ownerId: string;
  recipientDeviceId: string;
  pendingRegistrationId: string;
  recoverySessionId: string;
  serverChallengeHash: string;
  recoveredIdentitySigningKeyId: string;
  recoveryAuthorizationKeyId: string;
  candidateUserCheckpointSequence: number;
  candidateUserCheckpointHash: string;
  candidateUserEventHeadSequence: number;
  candidateUserEventHeadHash: string;
  recoveryCapabilityHash: string;
  pendingRegistrationBindingHash: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("recovery_session", "none");

  return transcriptBase("recovery_session", surface, "identity", params.ownerId, {
    subject_protocol: "refmd.recovery-session",
    subject_version: CURRENT_PROTOCOL_VERSION,
    owner_user_id: params.ownerId,
    recipient_device_id: params.recipientDeviceId,
    pending_registration_id: params.pendingRegistrationId,
    recovery_session_id: params.recoverySessionId,
    server_challenge_hash: params.serverChallengeHash,
    recovered_identity_signing_key_id: params.recoveredIdentitySigningKeyId,
    recovery_authorization_key_id: params.recoveryAuthorizationKeyId,
    candidate_user_checkpoint_hash: params.candidateUserCheckpointHash,
    candidate_user_checkpoint_sequence: params.candidateUserCheckpointSequence,
    candidate_user_event_head_hash: params.candidateUserEventHeadHash,
    candidate_user_event_head_sequence: params.candidateUserEventHeadSequence,
    pending_registration_binding_hash: params.pendingRegistrationBindingHash,
    recovery_capability_hash: params.recoveryCapabilityHash,
  });
}

export function buildRecoveryAuthorizationProofTranscript(params: {
  ownerId: string;
  recoveryAuthorizationKeyId: string;
  recipientDeviceId: string;
  pendingRegistrationBindingHash: string;
  serverChallengeHash: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("recovery_authorization_proof", "none");

  return transcriptBase("recovery_authorization_proof", surface, "identity", params.ownerId, {
    subject_protocol: "refmd.recovery-authorization-proof",
    subject_version: CURRENT_PROTOCOL_VERSION,
    recovery_authorization_key_id: params.recoveryAuthorizationKeyId,
    recipient_device_id: params.recipientDeviceId,
    pending_registration_binding_hash: params.pendingRegistrationBindingHash,
    server_challenge_hash: params.serverChallengeHash,
  });
}

export function buildDeviceKeyDeletionProofTranscript(params: {
  payload: Record<string, unknown>;
  actor: Record<string, unknown>;
}): StrictJsonValue {
  const proofKind = stringValue(
    params.payload.deletion_proof_kind,
    "device_key_deletion_kind_invalid",
  );
  const surface = getActiveSigningSurface("device_key_deletion_proof", proofKind);
  const deviceId = stringValue(params.payload.device_id, "device_key_deletion_device_invalid");
  const payloadBytes = canonicalizeStrictBytes(params.payload as StrictJsonValue);
  const deletedStorageClasses = params.payload.deleted_storage_classes;
  if (!Array.isArray(deletedStorageClasses)) {
    throw new Error("device_key_deletion_storage_classes_invalid");
  }

  return transcriptBase("device_key_deletion_proof", surface, "device", deviceId, {
    subject_hash: blake3Base64Url(payloadBytes),
    subject_protocol: "refmd.device-key-deletion-proof",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: params.actor,
    authority_boundary: {
      workspace_id: stringValue(
        params.payload.workspace_id,
        "device_key_deletion_workspace_invalid",
      ),
      rotation_kind: stringValue(
        params.payload.rotation_kind,
        "device_key_deletion_rotation_invalid",
      ),
      scope_kind: stringValue(params.payload.scope_kind, "device_key_deletion_scope_invalid"),
      scope_id: stringValue(params.payload.scope_id, "device_key_deletion_scope_invalid"),
      old_key_version: numberValue(
        params.payload.old_key_version,
        "device_key_deletion_version_invalid",
      ),
      rotation_completed_event_hash: stringValue(
        params.payload.rotation_completed_event_hash,
        "device_key_deletion_completion_hash_invalid",
      ),
      deleted_secret_ids_hash: stringValue(
        params.payload.deleted_secret_ids_hash,
        "device_key_deletion_secret_hash_invalid",
      ),
      deleted_storage_classes_hash: blake3Base64Url(
        canonicalizeStrictBytes({
          storage_classes: [...deletedStorageClasses].sort(),
        } as StrictJsonValue),
      ),
    },
  });
}
