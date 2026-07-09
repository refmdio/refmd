import { blake3Base64Url } from "./hash";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getActiveSigningSurface } from "./signing-surface";
import { CURRENT_PROTOCOL_VERSION } from "./suite";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";
import { computeSigningKeyId } from "./signature";
import { transcriptBase, type SigningOwnerKind } from "./signature-transcript-core";

export function buildRrpTranscript(params: {
  variant:
    | "http_user_device"
    | "http_share_participant_device"
    | "channel_user_device"
    | "channel_share_participant_device";
  ownerKind: SigningOwnerKind;
  ownerId: string;
  actor: Record<string, StrictJsonValue>;
  challenge: string;
  session: Record<string, StrictJsonValue>;
  resource?: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("rrp_request", params.variant);
  const transport = params.variant.startsWith("channel_") ? "phoenix_channel" : "http";
  const payload: Record<string, StrictJsonValue> = {
    challenge: params.challenge,
    rrp_variant: params.variant,
    transport,
    actor: params.actor,
    session: params.session,
  };
  if (!params.resource) throw new Error("rrp_resource_required");
  if (params.variant.startsWith("http_")) {
    payload.request = params.resource;
  } else if (params.variant.startsWith("channel_")) {
    payload.resource = params.resource;
  }
  return transcriptBase("rrp_request", surface, params.ownerKind, params.ownerId, payload);
}

export function buildGenesisDeviceBootstrapTranscript(params: {
  ownerId: string;
  deviceId: string;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceEcdhPublicKey: string;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  clientNonce: string;
  registrationChallengeHash: string;
  identitySigningKeyId: string;
  userIdentityPublicKeyHash: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("genesis_device_bootstrap", "none");
  const encryptionKeyId = computeHybridEncryptionKeyId(
    params.deviceHybridEncryptionPublicKeyMaterial,
  );
  const deviceSigningKeyId = computeSigningKeyId(params.deviceHybridSigningPublicKeyMaterial);
  const deviceHybridEncryptionPublicKeyMaterialHash = blake3Base64Url(
    canonicalizeStrictBytes(
      params.deviceHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
    ),
  );
  return transcriptBase("genesis_device_bootstrap", surface, "identity", params.ownerId, {
    subject_protocol: "refmd.genesis-device-bootstrap",
    subject_version: CURRENT_PROTOCOL_VERSION,
    client_nonce: params.clientNonce,
    user_id: params.ownerId,
    identity_signing_key_id: params.identitySigningKeyId,
    device_id: params.deviceId,
    device_signing_key_id: deviceSigningKeyId,
    device_hybrid_encryption_public_key_material_hash: deviceHybridEncryptionPublicKeyMaterialHash,
    device_encryption_key_id: encryptionKeyId,
    bootstrap_authority: {
      authority_kind: "first_device_no_existing_active_device",
      user_identity_public_key_hash: params.userIdentityPublicKeyHash,
      registration_challenge_hash: params.registrationChallengeHash,
    },
  });
}

export function buildDeviceApprovalTranscript(params: {
  ownerId: string;
  approverDeviceId: string;
  approvedDeviceId: string;
  approvedDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  approvedDeviceEcdhPublicKey: string;
  approvedDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  clientNonce: string;
  approvedDeviceRegistrationSasHash: string;
  pendingRegistrationId: string;
  pendingRegistrationChallengeHash: string;
  approvingOwnerKind: "device";
  approvingOwnerId: string;
  approvingSigningKeyId: string;
  approvingKeyCheckpointSequence: number;
  approvingKeyCheckpointHash: string;
  approvingDeviceKeyDirectoryProofHash: string;
  targetDeviceId: string;
  targetDeviceSigningKeyId: string;
  targetDeviceHybridSigningPublicKeyMaterialHash: string;
  targetDeviceHybridEncryptionPublicKeyMaterialHash: string;
  targetDeviceEncryptionKeyId: string;
  targetDeviceClientNonceHash: string;
  targetKeyCheckpointSequence: number;
  targetKeyCheckpointHash: string;
  umkDistributionDeliveryCommitment: StrictJsonValue;
  trustTransferDeliveryCommitment: StrictJsonValue;
  deviceApprovalKekInitialDeliveryCommitments: StrictJsonValue[];
}): StrictJsonValue {
  const surface = getActiveSigningSurface("device_approval", "none");
  return transcriptBase("device_approval", surface, "device", params.approverDeviceId, {
    approval_signature_surface: "device_approval",
    approved_device_registration_sas_hash: params.approvedDeviceRegistrationSasHash,
    device_approval_kek_initial_delivery_commitments:
      params.deviceApprovalKekInitialDeliveryCommitments,
    pending_registration_challenge_hash: params.pendingRegistrationChallengeHash,
    pending_registration_id: params.pendingRegistrationId,
    approving_owner_kind: params.approvingOwnerKind,
    approving_owner_id: params.approvingOwnerId,
    approving_signing_key_id: params.approvingSigningKeyId,
    approving_key_checkpoint_sequence: params.approvingKeyCheckpointSequence,
    approving_key_checkpoint_hash: params.approvingKeyCheckpointHash,
    approving_device_key_directory_proof_hash: params.approvingDeviceKeyDirectoryProofHash,
    target_device_id: params.targetDeviceId,
    target_device_signing_key_id: params.targetDeviceSigningKeyId,
    target_device_hybrid_signing_public_key_material_hash:
      params.targetDeviceHybridSigningPublicKeyMaterialHash,
    target_device_hybrid_encryption_public_key_material_hash:
      params.targetDeviceHybridEncryptionPublicKeyMaterialHash,
    target_device_encryption_key_id: params.targetDeviceEncryptionKeyId,
    target_device_client_nonce_hash: params.targetDeviceClientNonceHash,
    target_key_checkpoint_sequence: params.targetKeyCheckpointSequence,
    target_key_checkpoint_hash: params.targetKeyCheckpointHash,
    trust_transfer_delivery_commitment: params.trustTransferDeliveryCommitment,
    umk_distribution_delivery_commitment: params.umkDistributionDeliveryCommitment,
  });
}

export function buildDeviceRevocationTranscript(params: {
  ownerId: string;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  revokedDeviceId: string;
  revocationMode: string;
  revokedAtMs: number;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("device_revocation", "none");
  const subject = canonicalizeStrictBytes({
    actor: {
      device_id: params.actorDeviceId,
      signing_key_id: params.signingKeyId,
      user_id: params.actorUserId,
    },
    authority_boundary: {
      user_id: params.ownerId,
    },
    revocation: {
      device_id: params.revokedDeviceId,
      mode: params.revocationMode,
      revoked_at_ms: params.revokedAtMs,
    },
  } as unknown as StrictJsonValue);

  return transcriptBase("device_revocation", surface, "device", params.actorDeviceId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.device.revocation",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: {
      device_id: params.actorDeviceId,
      signing_key_id: params.signingKeyId,
      user_id: params.actorUserId,
    },
    authority_boundary: {
      user_id: params.ownerId,
    },
    revocation: {
      device_id: params.revokedDeviceId,
      mode: params.revocationMode,
      revoked_at_ms: params.revokedAtMs,
    },
  });
}
