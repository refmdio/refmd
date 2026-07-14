import { decodeBase64UrlStrict } from "./encoding";
import { blake3Base64Url } from "./hash";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { canonicalizeStrict, canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { computeSigningKeyId, type HybridSigningPublicKeyMaterial } from "./signature";

const APPROVAL_PROOF_KEYS = [
  "approval_signature_surface",
  "approval_surface_id",
  "approval_surface_variant",
  "approval_transcript_hash",
  "approval_transcript_owner",
  "approving_key_checkpoint_hash",
  "approving_key_checkpoint_sequence",
  "approving_owner_id",
  "approving_owner_kind",
  "approving_signing_key_id",
  "protocol",
  "surface_details",
  "target_device_client_nonce_hash",
  "target_device_encryption_key_id",
  "target_device_hybrid_encryption_public_key_material_hash",
  "target_device_hybrid_signing_public_key_material_hash",
  "target_device_id",
  "target_device_signing_key_id",
  "target_key_checkpoint_hash",
  "target_key_checkpoint_sequence",
  "version",
] as const;

const GENESIS_DETAILS_KEYS = [
  "kind",
  "registration_challenge_hash",
  "user_identity_public_key_hash",
] as const;

const DEVICE_APPROVAL_DETAILS_KEYS = [
  "approved_device_registration_sas_hash",
  "approving_device_key_directory_proof_hash",
  "device_approval_kek_initial_delivery_commitments",
  "kind",
  "pending_registration_challenge_hash",
  "pending_registration_id",
  "trust_transfer_delivery_commitment",
  "umk_distribution_delivery_commitment",
] as const;

const RECOVERY_DETAILS_KEYS = [
  "kind",
  "pending_registration_binding_hash",
  "pending_registration_challenge_hash",
  "pending_registration_id",
  "recovery_capability_hash",
  "recovery_session_transcript_hash",
] as const;

const UMK_DISTRIBUTION_COMMITMENT_KEYS = [
  "delivery_id",
  "delivery_record_hash",
  "key_checkpoint_hash",
  "purpose",
  "recipient_device_id",
  "sender_device_id",
  "variant",
] as const;

const TRUST_TRANSFER_COMMITMENT_KEYS = [
  "ake_session_id",
  "delivery_id",
  "delivery_record_hash",
  "document_rollback_pin_set_hash",
  "key_checkpoint_hash",
  "purpose",
  "recipient_device_id",
  "sender_device_id",
  "variant",
] as const;

const DEVICE_APPROVAL_KEK_COMMITMENT_KEYS = [
  "delivery_id",
  "delivery_record_hash",
  "key_checkpoint_hash",
  "key_version",
  "purpose",
  "recipient_device_id",
  "sender_device_id",
  "variant",
  "workspace_id",
] as const;

export function validateDeviceApprovalProofEnvelope(params: {
  proof: Record<string, unknown>;
  purpose: string;
  transcript: StrictJsonValue;
  targetDeviceId: string;
  targetDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  targetDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  targetDeviceClientNonce: string;
  approvingHybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial | null;
  approvalDeliveryCommitments?: Record<string, unknown> | null;
  approvalDeliveryArtifacts?: Record<string, unknown> | null;
}): boolean {
  const { proof, transcript } = params;
  const transcriptRecord = isRecord(transcript) ? transcript : null;
  const details = isRecord(proof.surface_details) ? proof.surface_details : null;
  if (!transcriptRecord || !details || !hasExactKeys(proof, APPROVAL_PROOF_KEYS)) {
    return false;
  }

  if (
    proof.protocol !== "refmd.device-approval-proof" ||
    proof.version !== 1 ||
    proof.approval_signature_surface !== params.purpose ||
    proof.approval_surface_id !== transcriptRecord.surface_id ||
    proof.approval_surface_variant !== transcriptRecord.surface_variant ||
    proof.approval_transcript_owner !== transcriptRecord.transcript_owner ||
    proof.approving_owner_kind !== transcriptRecord.owner_kind ||
    proof.approving_owner_id !== transcriptRecord.owner_id ||
    proof.approval_transcript_hash !== blake3Base64Url(canonicalizeStrictBytes(transcript))
  ) {
    return false;
  }

  if (
    !params.approvingHybridSigningPublicKeyMaterial ||
    proof.approving_signing_key_id !==
      computeSigningKeyId(params.approvingHybridSigningPublicKeyMaterial) ||
    proof.approving_owner_kind !== params.approvingHybridSigningPublicKeyMaterial.owner_kind ||
    proof.approving_owner_id !== params.approvingHybridSigningPublicKeyMaterial.owner_id
  ) {
    return false;
  }

  const expectedDetails =
    params.purpose === "genesis_device_bootstrap"
      ? { kind: "genesis_device_bootstrap", keys: GENESIS_DETAILS_KEYS }
      : params.purpose === "device_approval"
        ? { kind: "device_approval", keys: DEVICE_APPROVAL_DETAILS_KEYS }
        : params.purpose === "recovery_device_approval"
          ? { kind: "recovery_device_approval", keys: RECOVERY_DETAILS_KEYS }
          : null;
  if (!expectedDetails || !hasExactKeys(details, expectedDetails.keys)) return false;
  if (details.kind !== expectedDetails.kind) return false;
  if (
    !validateApprovalDeliveryCommitments(
      params.purpose,
      details,
      params.approvalDeliveryCommitments,
      params.approvalDeliveryArtifacts,
    )
  ) {
    return false;
  }

  const expectedTarget = {
    target_device_id: params.targetDeviceId,
    target_device_signing_key_id: computeSigningKeyId(
      params.targetDeviceHybridSigningPublicKeyMaterial,
    ),
    target_device_hybrid_signing_public_key_material_hash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.targetDeviceHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    target_device_hybrid_encryption_public_key_material_hash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.targetDeviceHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    target_device_encryption_key_id: computeHybridEncryptionKeyId(
      params.targetDeviceHybridEncryptionPublicKeyMaterial,
    ),
    target_device_client_nonce_hash: blake3Base64Url(
      decodeBase64UrlStrict(params.targetDeviceClientNonce, 16),
    ),
  } as const;

  return Object.entries(expectedTarget).every(([key, value]) => proof[key] === value);
}

function validateApprovalDeliveryCommitments(
  purpose: string,
  details: Record<string, unknown>,
  commitments: Record<string, unknown> | null | undefined,
  artifacts: Record<string, unknown> | null | undefined,
): boolean {
  if (purpose !== "device_approval") return true;
  if (!isRecord(commitments)) return false;

  const expectedKeys = [
    "device_approval_kek_initial_delivery_commitments",
    "trust_transfer_delivery_commitment",
    "umk_distribution_delivery_commitment",
  ] as const;

  if (!hasExactKeys(commitments, expectedKeys)) return false;
  if (
    !expectedKeys.every((key) => approvalCommitmentFieldEqual(key, commitments[key], details[key]))
  ) {
    return false;
  }

  return (
    validateApprovalCommitmentShapes(details) &&
    validateApprovalCommitmentShapes(commitments) &&
    validateApprovalDeliveryArtifactHashes(details, artifacts)
  );
}

function validateApprovalCommitmentShapes(value: Record<string, unknown>): boolean {
  const umk = value.umk_distribution_delivery_commitment;
  const trust = value.trust_transfer_delivery_commitment;
  const keks = value.device_approval_kek_initial_delivery_commitments;

  return (
    isRecord(umk) &&
    hasExactKeys(umk, UMK_DISTRIBUTION_COMMITMENT_KEYS) &&
    hasPurposeVariant(umk, "umk_distribution") &&
    isRecord(trust) &&
    hasExactKeys(trust, TRUST_TRANSFER_COMMITMENT_KEYS) &&
    hasPurposeVariant(trust, "trust_transfer") &&
    Array.isArray(keks) &&
    keks.every(
      (commitment) =>
        isRecord(commitment) &&
        hasExactKeys(commitment, DEVICE_APPROVAL_KEK_COMMITMENT_KEYS) &&
        hasPurposeVariant(commitment, "device_approval_kek_initial"),
    )
  );
}

function approvalCommitmentFieldEqual(key: string, left: unknown, right: unknown): boolean {
  if (key !== "device_approval_kek_initial_delivery_commitments") {
    return strictJsonEqual(left, right);
  }
  if (!Array.isArray(left) || !Array.isArray(right)) return false;

  try {
    const leftItems = left.map((item) => canonicalizeStrict(item as StrictJsonValue)).sort();
    const rightItems = right.map((item) => canonicalizeStrict(item as StrictJsonValue)).sort();
    return (
      leftItems.length === rightItems.length &&
      leftItems.every((item, index) => item === rightItems[index])
    );
  } catch {
    return false;
  }
}

function hasPurposeVariant(value: Record<string, unknown>, purpose: string): boolean {
  return value.purpose === purpose && value.variant === purpose;
}

function validateApprovalDeliveryArtifactHashes(
  details: Record<string, unknown>,
  artifacts: Record<string, unknown> | null | undefined,
): boolean {
  if (!isRecord(artifacts)) return false;

  const directChecks = [
    ["umk_distribution_delivery_commitment", "umk_distribution_initial_delivery"],
    ["trust_transfer_delivery_commitment", "trust_transfer_initial_delivery"],
  ] as const;

  for (const [commitmentKey, artifactKey] of directChecks) {
    const commitment = details[commitmentKey];
    const artifactHash = pendingDeliveryRecordHashFromArtifact(artifacts[artifactKey]);
    if (
      !isRecord(commitment) ||
      !artifactHash ||
      commitment.delivery_record_hash !== artifactHash
    ) {
      return false;
    }
  }

  const kekCommitments = details.device_approval_kek_initial_delivery_commitments;
  const kekArtifacts = artifacts.device_approval_kek_initial_deliveries;
  if (!Array.isArray(kekCommitments) || !Array.isArray(kekArtifacts)) return false;

  const artifactByWorkspace = new Map<string, unknown>();
  for (const entry of kekArtifacts) {
    if (!isRecord(entry) || typeof entry.workspace_id !== "string") return false;
    if (artifactByWorkspace.has(entry.workspace_id)) return false;
    artifactByWorkspace.set(entry.workspace_id, entry.delivery);
  }
  if (artifactByWorkspace.size !== kekCommitments.length) return false;

  return kekCommitments.every((commitment) => {
    if (!isRecord(commitment) || typeof commitment.workspace_id !== "string") return false;
    const artifactHash = pendingDeliveryRecordHashFromArtifact(
      artifactByWorkspace.get(commitment.workspace_id),
    );
    return Boolean(artifactHash && commitment.delivery_record_hash === artifactHash);
  });
}

export function pendingDeliveryRecordHashFromArtifact(artifact: unknown): string | null {
  if (!isRecord(artifact)) return null;
  const deliveryRecord = artifact.initial_key_delivery;
  if (
    !isRecord(deliveryRecord) ||
    !isRecord(deliveryRecord.metadata) ||
    !isRecord(deliveryRecord.aead)
  ) {
    return null;
  }

  try {
    const metadata = { ...deliveryRecord.metadata };
    delete metadata.key_confirmation_hash;
    return blake3Base64Url(
      canonicalizeStrictBytes({ metadata, aead: deliveryRecord.aead } as StrictJsonValue),
    );
  } catch {
    return null;
  }
}

function strictJsonEqual(left: unknown, right: unknown): boolean {
  try {
    return (
      canonicalizeStrict(left as StrictJsonValue) === canonicalizeStrict(right as StrictJsonValue)
    );
  } catch {
    return false;
  }
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    keys.length === sortedExpected.length &&
    keys.every((key, index) => key === sortedExpected[index])
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
