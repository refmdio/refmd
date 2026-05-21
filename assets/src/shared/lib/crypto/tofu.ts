import {
  type TofuEntry,
  DEFAULT_TOFU_NAMESPACE,
  getTofuEntry,
  saveTofuEntry,
  updateLastSeen,
} from "./trust-store";
import { calculateFingerprint, formatFingerprint } from "./fingerprint";
import { base64UrlDecode, constantTimeEqual } from "./encoding";
import { isValidX25519PublicKey } from "./key-validation";
import { canonicalizeStrict, canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { blake3Base64Url } from "./hash";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { validateDeviceApprovalProofEnvelope } from "./approval-proof-validation";
import {
  buildDeviceApprovalTranscript,
  buildGenesisDeviceBootstrapTranscript,
  buildPendingRegistrationBindingHash,
  buildRecoveryDeviceApprovalTranscript,
  computeSigningKeyId,
  ed25519PublicKeyFromMaterial,
  verifyDeviceApprovalSignature,
  verifyGenesisDeviceBootstrapSignature,
  verifyRecoveryDeviceApprovalSignature,
  type HybridSigningPublicKeyMaterial,
} from "./signature";
import type { DeviceInfo } from "@/shared/api/devices";
type TofuStatus = "first_seen" | "known_trusted" | "identity_key_changed" | "ecdh_key_mismatch";
interface TofuVerifyResult {
  status: TofuStatus;
  storedEntry?: TofuEntry;
  newEntry: TofuEntry;
  oldFingerprint?: string;
  newFingerprint?: string;
}
export async function verifyTofu(
  userId: string,
  deviceId: string,
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial,
  ecdhPublicKey: Uint8Array,
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<TofuVerifyResult> {
  if (!isValidX25519PublicKey(ecdhPublicKey)) {
    throw new Error("Invalid X25519 ECDH public key");
  }
  const now = Date.now();
  const newEntry: TofuEntry = {
    userId,
    deviceId,
    hybridSigningPublicKeyMaterial,
    ecdhPublicKey,
    firstSeenAt: now,
    lastSeenAt: now,
  };
  const storedEntry = await getTofuEntry(userId, deviceId, namespace);
  if (!storedEntry) {
    return { status: "first_seen", newEntry };
  }
  const storedSigningPublic = ed25519PublicKeyFromMaterial(
    storedEntry.hybridSigningPublicKeyMaterial,
  );
  const signingKeyMatches =
    canonicalizeStrict(storedEntry.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue) ===
    canonicalizeStrict(hybridSigningPublicKeyMaterial as unknown as StrictJsonValue);
  const ecdhKeyMatches = constantTimeEqual(storedEntry.ecdhPublicKey, ecdhPublicKey);
  if (signingKeyMatches && ecdhKeyMatches) {
    return {
      status: "known_trusted",
      storedEntry,
      newEntry: { ...newEntry, firstSeenAt: storedEntry.firstSeenAt },
    };
  }
  if (!signingKeyMatches) {
    const ed25519Public = ed25519PublicKeyFromMaterial(hybridSigningPublicKeyMaterial);
    const oldFp = formatFingerprint(calculateFingerprint(storedSigningPublic));
    const newFp = formatFingerprint(calculateFingerprint(ed25519Public));
    return {
      status: "identity_key_changed",
      storedEntry,
      newEntry,
      oldFingerprint: oldFp,
      newFingerprint: newFp,
    };
  }
  return { status: "ecdh_key_mismatch", storedEntry, newEntry };
}
export async function trustDevice(
  entry: TofuEntry,
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<void> {
  await saveTofuEntry(entry, namespace);
}
export async function updateDeviceLastSeen(
  userId: string,
  deviceId: string,
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<void> {
  await updateLastSeen(userId, deviceId, namespace);
}
export async function handleTofuResult(
  result: TofuVerifyResult,
  namespace = DEFAULT_TOFU_NAMESPACE,
  options: { persistFirstSeen?: boolean } = {},
): Promise<TofuVerifyResult> {
  switch (result.status) {
    case "first_seen":
      if (options.persistFirstSeen === true) {
        await trustDevice(result.newEntry, namespace);
      }
      break;
    case "known_trusted":
      await updateDeviceLastSeen(result.newEntry.userId, result.newEntry.deviceId, namespace);
      break;
    case "identity_key_changed":
    case "ecdh_key_mismatch":
      break;
  }
  return result;
}
class TofuHardFailError extends Error {
  deviceName: string;
  status: "identity_key_changed" | "ecdh_key_mismatch";
  constructor(deviceName: string, status: "identity_key_changed" | "ecdh_key_mismatch") {
    const msg =
      status === "identity_key_changed"
        ? `${deviceName}: Identity key changed`
        : `${deviceName}: ECDH key mismatch`;
    super(msg);
    this.name = "TofuHardFailError";
    this.deviceName = deviceName;
    this.status = status;
  }
}
export async function verifyAllDeviceTofu(
  userId: string,
  devices: DeviceInfo[],
  identityPublicMaterial: HybridSigningPublicKeyMaterial | null,
): Promise<string[]> {
  const warnings: string[] = [];
  const deviceMaterials = new Map(
    devices
      .filter((device) => device.hybrid_signing_public_key_material)
      .map((device) => [
        device.id,
        device.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
      ]),
  );
  for (const d of devices) {
    if (!d.hybrid_signing_public_key_material) continue;
    try {
      const hybridSigningPublicKeyMaterial =
        d.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
      const ecdhPk = base64UrlDecode(d.hybrid_encryption_public_key_material.x25519_public);
      const result = await verifyTofu(userId, d.id, hybridSigningPublicKeyMaterial, ecdhPk);
      if (result.status === "identity_key_changed" || result.status === "ecdh_key_mismatch") {
        throw new TofuHardFailError(d.name, result.status);
      }
      if (!d.approval_signature || !d.client_nonce) {
        warnings.push(`${d.name}: Missing identity signature`);
        continue;
      }
      if (!identityPublicMaterial) {
        await handleTofuResult(result);
        continue;
      }
      const sigValid = verifyDeviceIdentityHybridSignature({
        device: d,
        devicePublicMaterial:
          d.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
        identityPublicMaterial,
        deviceMaterials,
      });
      if (!sigValid) {
        warnings.push(`${d.name}: Invalid identity signature`);
        continue;
      }
      await handleTofuResult(result);
    } catch (e) {
      if (e instanceof TofuHardFailError) throw e;
      warnings.push(`${d.name}: Key verification unavailable`);
    }
  }
  return warnings;
}

function verifyDeviceIdentityHybridSignature(params: {
  device: DeviceInfo;
  devicePublicMaterial: HybridSigningPublicKeyMaterial;
  identityPublicMaterial: HybridSigningPublicKeyMaterial;
  deviceMaterials: Map<string, HybridSigningPublicKeyMaterial>;
}): boolean {
  const deviceHybridEncryptionPublicKeyMaterial = params.device
    .hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial;
  const deviceEcdhPublicKey = deviceHybridEncryptionPublicKeyMaterial.x25519_public;
  const clientNonce = params.device.client_nonce;
  if (!deviceEcdhPublicKey || !clientNonce) return false;
  const signature = params.device.approval_signature as never;
  if (
    typeof params.device.approval_signature_surface !== "string" ||
    !isRecord(params.device.approval_proof)
  ) {
    return false;
  }
  const purpose = params.device.approval_signature_surface;
  const proof = params.device.approval_proof as unknown as Record<string, unknown>;
  const details = isRecord(proof.surface_details) ? proof.surface_details : null;

  const candidate =
    purpose === "genesis_device_bootstrap"
      ? {
          signingPurpose: "genesis_device_bootstrap",
          publicKeyMaterial: params.identityPublicMaterial,
          transcript: buildGenesisDeviceBootstrapTranscript({
            ownerId: params.identityPublicMaterial.owner_id,
            deviceId: params.device.id,
            deviceHybridSigningPublicKeyMaterial: params.devicePublicMaterial,
            deviceEcdhPublicKey,
            deviceHybridEncryptionPublicKeyMaterial,
            clientNonce,
            registrationChallengeHash: details?.registration_challenge_hash as string,
            identitySigningKeyId: proof.approving_signing_key_id as string,
            userIdentityPublicKeyHash: details?.user_identity_public_key_hash as string,
          }),
        }
      : purpose === "device_approval" && details?.kind === "device_approval"
        ? {
            signingPurpose: "device_approval",
            publicKeyMaterial: params.deviceMaterials.get(proof.approving_owner_id as string),
            transcript: buildDeviceApprovalTranscript({
              ownerId: params.identityPublicMaterial.owner_id,
              approverDeviceId: proof.approving_owner_id as string,
              approvedDeviceId: params.device.id,
              approvedDeviceHybridSigningPublicKeyMaterial: params.devicePublicMaterial,
              approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
              approvedDeviceHybridEncryptionPublicKeyMaterial:
                deviceHybridEncryptionPublicKeyMaterial,
              clientNonce,
              ...deviceApprovalContextParams(proof, details, {
                targetDeviceId: params.device.id,
                targetDeviceHybridSigningPublicKeyMaterial: params.devicePublicMaterial,
                targetDeviceHybridEncryptionPublicKeyMaterial:
                  deviceHybridEncryptionPublicKeyMaterial,
                clientNonce,
              }),
            }),
          }
        : purpose === "recovery_device_approval" && details?.kind === "recovery_device_approval"
          ? {
              signingPurpose: "recovery_device_approval",
              publicKeyMaterial: params.identityPublicMaterial,
              transcript: buildRecoveryDeviceApprovalTranscript({
                ownerId: params.identityPublicMaterial.owner_id,
                approvingSigningKeyId: proof.approving_signing_key_id as string,
                approvingKeyCheckpointSequence: proof.approving_key_checkpoint_sequence as number,
                approvingKeyCheckpointHash: proof.approving_key_checkpoint_hash as string,
                pendingRegistrationId: details.pending_registration_id as string,
                pendingRegistrationChallengeHash:
                  details.pending_registration_challenge_hash as string,
                recoverySessionTranscriptHash: details.recovery_session_transcript_hash as string,
                recoveryCapabilityHash: details.recovery_capability_hash as string,
                pendingRegistrationBindingHash: buildPendingRegistrationBindingHash({
                  userId: params.identityPublicMaterial.owner_id,
                  pendingRegistrationId: details.pending_registration_id as string,
                  pendingRegistrationChallengeHash:
                    details.pending_registration_challenge_hash as string,
                  targetDeviceId: params.device.id,
                  targetDeviceSigningKeyId: computeSigningKeyId(params.devicePublicMaterial),
                  targetDeviceHybridSigningPublicKeyMaterial: params.devicePublicMaterial,
                  targetDeviceHybridEncryptionPublicKeyMaterial:
                    deviceHybridEncryptionPublicKeyMaterial,
                  targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(
                    deviceHybridEncryptionPublicKeyMaterial,
                  ),
                  targetDeviceClientNonce: clientNonce,
                  targetKeyCheckpointSequence: proof.target_key_checkpoint_sequence as number,
                  targetKeyCheckpointHash: proof.target_key_checkpoint_hash as string,
                }),
                approvedDeviceId: params.device.id,
                approvedDeviceHybridSigningPublicKeyMaterial: params.devicePublicMaterial,
                approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
                approvedDeviceHybridEncryptionPublicKeyMaterial:
                  deviceHybridEncryptionPublicKeyMaterial,
                clientNonce,
                targetKeyCheckpointSequence: proof.target_key_checkpoint_sequence as number,
                targetKeyCheckpointHash: proof.target_key_checkpoint_hash as string,
              }),
            }
          : null;

  if (
    !candidate ||
    !candidate.publicKeyMaterial ||
    proof.approval_signature_surface !== purpose ||
    !validateDeviceApprovalProofEnvelope({
      proof,
      purpose,
      transcript: candidate.transcript,
      targetDeviceId: params.device.id,
      targetDeviceHybridSigningPublicKeyMaterial: params.devicePublicMaterial,
      targetDeviceHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionPublicKeyMaterial,
      targetDeviceClientNonce: clientNonce,
      approvingHybridSigningPublicKeyMaterial: candidate.publicKeyMaterial,
      approvalDeliveryCommitments: params.device.approval_delivery_commitments ?? null,
      approvalDeliveryArtifacts: params.device.approval_delivery_artifacts ?? null,
    }) ||
    proof.approval_transcript_hash !==
      blake3Base64Url(canonicalizeStrictBytes(candidate.transcript))
  ) {
    return false;
  }

  const verificationParams = {
    transcript: candidate.transcript,
    signature,
    publicKeyMaterial: candidate.publicKeyMaterial,
  };
  if (candidate.signingPurpose === "genesis_device_bootstrap") {
    return verifyGenesisDeviceBootstrapSignature(verificationParams);
  }
  if (candidate.signingPurpose === "device_approval") {
    return verifyDeviceApprovalSignature(verificationParams);
  }
  return verifyRecoveryDeviceApprovalSignature(verificationParams);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deviceApprovalContextParams(
  proof: Record<string, unknown>,
  details: Record<string, unknown>,
  target: {
    targetDeviceId: string;
    targetDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    targetDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    clientNonce: string;
  },
): {
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
} {
  return {
    approvedDeviceRegistrationSasHash: details.approved_device_registration_sas_hash as string,
    pendingRegistrationId: details.pending_registration_id as string,
    pendingRegistrationChallengeHash: details.pending_registration_challenge_hash as string,
    approvingOwnerKind: proof.approving_owner_kind as "device",
    approvingOwnerId: proof.approving_owner_id as string,
    approvingSigningKeyId: proof.approving_signing_key_id as string,
    approvingKeyCheckpointSequence: proof.approving_key_checkpoint_sequence as number,
    approvingKeyCheckpointHash: proof.approving_key_checkpoint_hash as string,
    approvingDeviceKeyDirectoryProofHash:
      details.approving_device_key_directory_proof_hash as string,
    targetDeviceId: target.targetDeviceId,
    targetDeviceSigningKeyId: computeSigningKeyId(
      target.targetDeviceHybridSigningPublicKeyMaterial,
    ),
    targetDeviceHybridSigningPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        target.targetDeviceHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceHybridEncryptionPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        target.targetDeviceHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(
      target.targetDeviceHybridEncryptionPublicKeyMaterial,
    ),
    targetDeviceClientNonceHash: blake3Base64Url(base64UrlDecode(target.clientNonce)),
    targetKeyCheckpointSequence: proof.target_key_checkpoint_sequence as number,
    targetKeyCheckpointHash: proof.target_key_checkpoint_hash as string,
    umkDistributionDeliveryCommitment:
      details.umk_distribution_delivery_commitment as StrictJsonValue,
    trustTransferDeliveryCommitment: details.trust_transfer_delivery_commitment as StrictJsonValue,
    deviceApprovalKekInitialDeliveryCommitments:
      details.device_approval_kek_initial_delivery_commitments as StrictJsonValue[],
  };
}
