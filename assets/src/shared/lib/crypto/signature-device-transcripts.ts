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
  registrationId: string;
  compoundIntentId: string;
  mutationId: string;
  genesisCompoundContextHash: string;
  ownerId: string;
  workspaceId: string;
  ownerRoleId: string;
  deviceId: string;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceEcdhPublicKey: string;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  clientNonce: string;
  registrationChallengeHash: string;
  identitySigningKeyId: string;
  userIdentityPublicKeyHash: string;
  userDeviceKeyAddedEventHash: string;
  workspaceDeviceKeyAddedEventHash: string;
  ownerMemberAddedEventHash: string;
  workspaceMemberEnvelopeCommitmentHash: string;
  userAuditCheckpoint: { sequence: number; checkpoint_hash: string };
  workspaceAuditCheckpoint: { sequence: number; checkpoint_hash: string };
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
    registration_id: params.registrationId,
    compound_intent_id: params.compoundIntentId,
    mutation_id: params.mutationId,
    genesis_compound_context_hash: params.genesisCompoundContextHash,
    client_nonce: params.clientNonce,
    user_id: params.ownerId,
    workspace_id: params.workspaceId,
    owner_role_id: params.ownerRoleId,
    identity_signing_key_id: params.identitySigningKeyId,
    device_id: params.deviceId,
    device_signing_key_id: deviceSigningKeyId,
    device_hybrid_encryption_public_key_material_hash: deviceHybridEncryptionPublicKeyMaterialHash,
    device_encryption_key_id: encryptionKeyId,
    user_device_key_added_event_hash: params.userDeviceKeyAddedEventHash,
    workspace_device_key_added_event_hash: params.workspaceDeviceKeyAddedEventHash,
    owner_member_added_event_hash: params.ownerMemberAddedEventHash,
    workspace_member_envelope_commitment_hash: params.workspaceMemberEnvelopeCommitmentHash,
    user_audit_checkpoint: params.userAuditCheckpoint,
    workspace_audit_checkpoint: params.workspaceAuditCheckpoint,
    bootstrap_authority: {
      authority_kind: "first_device_no_existing_active_device",
      user_identity_public_key_hash: params.userIdentityPublicKeyHash,
      registration_challenge_hash: params.registrationChallengeHash,
    },
  });
}

const GENESIS_DEVICE_BOOTSTRAP_DETAIL_KEYS = [
  "compound_intent_id",
  "genesis_compound_context_hash",
  "kind",
  "mutation_id",
  "owner_member_added_event_hash",
  "owner_role_id",
  "registration_id",
  "registration_challenge_hash",
  "user_audit_checkpoint",
  "user_device_key_added_event_hash",
  "user_identity_public_key_hash",
  "workspace_audit_checkpoint",
  "workspace_device_key_added_event_hash",
  "workspace_id",
  "workspace_member_envelope_commitment_hash",
] as const;

export function buildGenesisDeviceBootstrapTranscriptFromProof(params: {
  ownerId: string;
  deviceId: string;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceEcdhPublicKey: string;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  clientNonce: string;
  identitySigningKeyId: unknown;
  surfaceDetails: unknown;
}): StrictJsonValue {
  const details = exactRecord(params.surfaceDetails, GENESIS_DEVICE_BOOTSTRAP_DETAIL_KEYS);
  if (details.kind !== "genesis_device_bootstrap") {
    throw new Error("genesis_device_bootstrap_details_invalid");
  }

  return buildGenesisDeviceBootstrapTranscript({
    registrationId: requiredString(details.registration_id),
    compoundIntentId: requiredString(details.compound_intent_id),
    mutationId: requiredString(details.mutation_id),
    genesisCompoundContextHash: requiredString(details.genesis_compound_context_hash),
    ownerId: params.ownerId,
    workspaceId: requiredString(details.workspace_id),
    ownerRoleId: requiredString(details.owner_role_id),
    deviceId: params.deviceId,
    deviceHybridSigningPublicKeyMaterial: params.deviceHybridSigningPublicKeyMaterial,
    deviceEcdhPublicKey: params.deviceEcdhPublicKey,
    deviceHybridEncryptionPublicKeyMaterial: params.deviceHybridEncryptionPublicKeyMaterial,
    clientNonce: params.clientNonce,
    registrationChallengeHash: requiredString(details.registration_challenge_hash),
    identitySigningKeyId: requiredString(params.identitySigningKeyId),
    userIdentityPublicKeyHash: requiredString(details.user_identity_public_key_hash),
    userDeviceKeyAddedEventHash: requiredString(details.user_device_key_added_event_hash),
    workspaceDeviceKeyAddedEventHash: requiredString(details.workspace_device_key_added_event_hash),
    ownerMemberAddedEventHash: requiredString(details.owner_member_added_event_hash),
    workspaceMemberEnvelopeCommitmentHash: requiredString(
      details.workspace_member_envelope_commitment_hash,
    ),
    userAuditCheckpoint: checkpointReference(details.user_audit_checkpoint),
    workspaceAuditCheckpoint: checkpointReference(details.workspace_audit_checkpoint),
  });
}

function checkpointReference(value: unknown): { sequence: number; checkpoint_hash: string } {
  const checkpoint = exactRecord(value, ["checkpoint_hash", "sequence"] as const);
  if (!Number.isSafeInteger(checkpoint.sequence) || (checkpoint.sequence as number) < 1) {
    throw new Error("genesis_device_bootstrap_checkpoint_invalid");
  }
  return {
    sequence: checkpoint.sequence as number,
    checkpoint_hash: requiredString(checkpoint.checkpoint_hash),
  };
}

function exactRecord<const Keys extends readonly string[]>(
  value: unknown,
  keys: Keys,
): Record<Keys[number], unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).sort(compareStrings).join("\u0000") !==
      [...keys].sort(compareStrings).join("\u0000")
  ) {
    throw new Error("genesis_device_bootstrap_details_invalid");
  }
  return value as Record<Keys[number], unknown>;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("genesis_device_bootstrap_details_invalid");
  }
  return value;
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
  actor: StrictJsonValue;
  revokedDevice: StrictJsonValue;
  authorityBoundary: StrictJsonValue;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("device_revocation", "none");
  const actor = params.actor as Record<string, unknown>;
  const subject = canonicalizeStrictBytes({
    actor: params.actor,
    revoked_device: params.revokedDevice,
    authority_boundary: params.authorityBoundary,
  } as unknown as StrictJsonValue);

  return transcriptBase("device_revocation", surface, "device", actor.device_id as string, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.device-revocation",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: params.actor,
    authority_boundary: params.authorityBoundary,
    revoked_device: params.revokedDevice,
  });
}
