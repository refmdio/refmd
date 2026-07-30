import type { WorkerKeyState } from "../state";
import { getAllTofuEntries, importTofuEntries } from "../../trust-store";
import { handleTofuResult, trustDevice, updateDeviceLastSeen, verifyTofu } from "../../tofu";
import { base64UrlDecode, base64UrlEncode } from "../../encoding";
import { blake3Base64Url } from "../../hash";
import { canonicalizeStrict, canonicalizeStrictBytes, type StrictJsonValue } from "../../jcs";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "../../hybrid-encryption";
import { validateDeviceApprovalProofEnvelope } from "../../approval-proof-validation";
import {
  buildDeviceApprovalTranscript,
  buildGenesisDeviceBootstrapTranscriptFromProof,
  buildPendingRegistrationBindingHash,
  buildRecoveryDeviceApprovalTranscript,
  computeSigningKeyId,
  verifyDeviceApprovalSignature,
  verifyGenesisDeviceBootstrapSignature,
  verifyRecoveryDeviceApprovalSignature,
  type HybridSignature,
  type HybridSigningPublicKeyMaterial,
} from "../../signature";
import { type HandlerPayload, requireUserId } from "./utils";

export async function handleTofuVerify(p: HandlerPayload): Promise<unknown> {
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;
  const hybridSigningPublicKeyMaterial =
    p.hybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial;
  const ecdhPublicKey = p.ecdhPublicKey as Uint8Array;
  const namespace = p.namespace as string | undefined;

  const result = await verifyTofu(
    userId,
    deviceId,
    hybridSigningPublicKeyMaterial,
    ecdhPublicKey,
    namespace,
  );
  return { status: result.status };
}

export async function handleTofuVerifyAllDevices(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const rawDevices = p.devices as Array<{
    userId: string;
    deviceId: string;
    name?: string;
    ecdhPublicKey: Uint8Array;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    identitySignature: HybridSignature;
    identitySignaturePurpose: string;
    identitySignatureContext: Record<string, unknown>;
    approvalDeliveryCommitments?: Record<string, unknown> | null;
    approvalDeliveryArtifacts?: Record<string, unknown> | null;
    clientNonce: string;
  }>;
  const userId = requireUserId(state);
  const identityPublicMaterial = state.identityHybridSigningState?.publicKeyMaterial;
  if (!identityPublicMaterial) {
    throw new Error("identity_signing_key_unavailable");
  }

  const errors: string[] = [];
  const deviceMaterials = new Map(
    rawDevices.map((device) => [device.deviceId, device.deviceHybridSigningPublicKeyMaterial]),
  );
  for (const device of rawDevices) {
    if (!verifyDeviceApprovalSurface(state, device, identityPublicMaterial, deviceMaterials)) {
      throw new Error(`invalid_device_approval_signature:${device.deviceId}`);
    }

    const result = await verifyTofu(
      userId,
      device.deviceId,
      device.deviceHybridSigningPublicKeyMaterial,
      device.ecdhPublicKey,
    );
    if (result.status === "identity_key_changed" || result.status === "ecdh_key_mismatch") {
      errors.push(`${device.name ?? device.deviceId}: ${result.status}`);
    } else {
      await handleTofuResult(result, undefined, { persistFirstSeen: false });
    }
  }
  return { errors };
}

function verifyDeviceApprovalSurface(
  state: WorkerKeyState,
  device: {
    userId: string;
    deviceId: string;
    ecdhPublicKey: Uint8Array;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    identitySignature: HybridSignature;
    identitySignaturePurpose: string;
    identitySignatureContext: Record<string, unknown>;
    approvalDeliveryCommitments?: Record<string, unknown> | null;
    approvalDeliveryArtifacts?: Record<string, unknown> | null;
    clientNonce: string;
  },
  identityPublicMaterial: HybridSigningPublicKeyMaterial,
  deviceMaterials: Map<string, HybridSigningPublicKeyMaterial>,
): boolean {
  if (
    typeof device.identitySignaturePurpose !== "string" ||
    !isRecord(device.identitySignatureContext)
  ) {
    return false;
  }

  const deviceEcdhPublicKey = base64UrlEncode(device.ecdhPublicKey);
  const purpose = device.identitySignaturePurpose;
  const context = device.identitySignatureContext;
  const details = isRecord(context.surface_details) ? context.surface_details : context;
  const approvalIdentityPublicMaterial = resolveIdentityApprovalPublicMaterial(
    state,
    context.approving_signing_key_id,
  );
  const candidate =
    purpose === "genesis_device_bootstrap"
      ? {
          signingPurpose: "genesis_device_bootstrap",
          publicKeyMaterial: approvalIdentityPublicMaterial,
          transcript: buildGenesisDeviceBootstrapTranscriptFromProof({
            ownerId: identityPublicMaterial.owner_id,
            deviceId: device.deviceId,
            deviceHybridSigningPublicKeyMaterial: device.deviceHybridSigningPublicKeyMaterial,
            deviceEcdhPublicKey,
            deviceHybridEncryptionPublicKeyMaterial: device.deviceHybridEncryptionPublicKeyMaterial,
            clientNonce: device.clientNonce,
            identitySigningKeyId: context.approving_signing_key_id as string,
            surfaceDetails: details,
          }),
        }
      : purpose === "device_approval"
        ? {
            signingPurpose: "device_approval",
            publicKeyMaterial: deviceMaterials.get(context.approving_owner_id as string),
            transcript: buildDeviceApprovalTranscript({
              ownerId: identityPublicMaterial.owner_id,
              approverDeviceId: context.approving_owner_id as string,
              approvedDeviceId: device.deviceId,
              approvedDeviceHybridSigningPublicKeyMaterial:
                device.deviceHybridSigningPublicKeyMaterial,
              approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
              approvedDeviceHybridEncryptionPublicKeyMaterial:
                device.deviceHybridEncryptionPublicKeyMaterial,
              clientNonce: device.clientNonce,
              ...deviceApprovalContextParams(context),
              ...targetApprovalFields({
                targetDeviceId: device.deviceId,
                targetDeviceHybridSigningPublicKeyMaterial:
                  device.deviceHybridSigningPublicKeyMaterial,
                targetDeviceHybridEncryptionPublicKeyMaterial:
                  device.deviceHybridEncryptionPublicKeyMaterial,
                targetDeviceClientNonce: device.clientNonce,
              }),
            }),
          }
        : purpose === "recovery_device_approval"
          ? {
              signingPurpose: "recovery_device_approval",
              publicKeyMaterial: approvalIdentityPublicMaterial,
              transcript: buildRecoveryDeviceApprovalTranscript({
                ownerId: identityPublicMaterial.owner_id,
                approvingSigningKeyId: context.approving_signing_key_id as string,
                approvingKeyCheckpointSequence: context.approving_key_checkpoint_sequence as number,
                approvingKeyCheckpointHash: context.approving_key_checkpoint_hash as string,
                pendingRegistrationId: details.pending_registration_id as string,
                pendingRegistrationChallengeHash:
                  details.pending_registration_challenge_hash as string,
                recoverySessionTranscriptHash: details.recovery_session_transcript_hash as string,
                recoveryCapabilityHash: details.recovery_capability_hash as string,
                pendingRegistrationBindingHash: buildPendingRegistrationBindingHash({
                  userId: identityPublicMaterial.owner_id,
                  pendingRegistrationId: details.pending_registration_id as string,
                  pendingRegistrationChallengeHash:
                    details.pending_registration_challenge_hash as string,
                  targetDeviceId: device.deviceId,
                  targetDeviceSigningKeyId: computeSigningKeyId(
                    device.deviceHybridSigningPublicKeyMaterial,
                  ),
                  targetDeviceHybridSigningPublicKeyMaterial:
                    device.deviceHybridSigningPublicKeyMaterial,
                  targetDeviceHybridEncryptionPublicKeyMaterial:
                    device.deviceHybridEncryptionPublicKeyMaterial,
                  targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(
                    device.deviceHybridEncryptionPublicKeyMaterial,
                  ),
                  targetDeviceClientNonce: device.clientNonce,
                  targetKeyCheckpointSequence: context.target_key_checkpoint_sequence as number,
                  targetKeyCheckpointHash: context.target_key_checkpoint_hash as string,
                }),
                approvedDeviceId: device.deviceId,
                approvedDeviceHybridSigningPublicKeyMaterial:
                  device.deviceHybridSigningPublicKeyMaterial,
                approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
                approvedDeviceHybridEncryptionPublicKeyMaterial:
                  device.deviceHybridEncryptionPublicKeyMaterial,
                clientNonce: device.clientNonce,
                targetKeyCheckpointSequence: context.target_key_checkpoint_sequence as number,
                targetKeyCheckpointHash: context.target_key_checkpoint_hash as string,
              }),
            }
          : null;

  if (
    !candidate ||
    !candidate.publicKeyMaterial ||
    !validateDeviceApprovalProofEnvelope({
      proof: context,
      purpose,
      transcript: candidate.transcript as StrictJsonValue,
      targetDeviceId: device.deviceId,
      targetDeviceHybridSigningPublicKeyMaterial: device.deviceHybridSigningPublicKeyMaterial,
      targetDeviceHybridEncryptionPublicKeyMaterial: device.deviceHybridEncryptionPublicKeyMaterial,
      targetDeviceClientNonce: device.clientNonce,
      approvingHybridSigningPublicKeyMaterial: candidate.publicKeyMaterial,
      approvalDeliveryCommitments: device.approvalDeliveryCommitments ?? null,
      approvalDeliveryArtifacts: device.approvalDeliveryArtifacts ?? null,
    }) ||
    (typeof context.approval_transcript_hash === "string"
      ? context.approval_transcript_hash !==
        blake3Base64Url(canonicalizeStrictBytes(candidate.transcript as StrictJsonValue))
      : !strictJsonEqual(context, candidate.transcript))
  ) {
    return false;
  }

  const verificationParams = {
    transcript: candidate.transcript,
    signature: device.identitySignature,
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

export function resolveIdentityApprovalPublicMaterial(
  state: WorkerKeyState,
  signingKeyId: unknown,
): HybridSigningPublicKeyMaterial | null {
  if (typeof signingKeyId !== "string" || !state.userId) return null;

  const current = state.identityHybridSigningState;
  if (current?.signingKeyId === signingKeyId) return current.publicKeyMaterial;

  const checkpoint = state.identityRotationTrustedCheckpointPayload;
  if (
    checkpoint?.scope_kind !== "user" ||
    checkpoint.scope_id !== state.userId ||
    !Array.isArray(checkpoint.identity_keys)
  ) {
    return null;
  }

  const entry = checkpoint.identity_keys.find(
    (candidate): candidate is Record<string, unknown> =>
      isRecord(candidate) && candidate.key_id === signingKeyId,
  );
  if (!entry || !isRecord(entry.key_material)) return null;

  const material = entry.key_material as unknown as HybridSigningPublicKeyMaterial;
  try {
    if (
      material.owner_kind !== "identity" ||
      material.owner_id !== state.userId ||
      computeSigningKeyId(material) !== signingKeyId
    ) {
      return null;
    }
  } catch {
    return null;
  }
  return material;
}

function deviceApprovalContextParams(value: Record<string, unknown>): {
  approvedDeviceRegistrationSasHash: string;
  pendingRegistrationId: string;
  pendingRegistrationChallengeHash: string;
  approvingOwnerKind: "device";
  approvingOwnerId: string;
  approvingSigningKeyId: string;
  approvingKeyCheckpointSequence: number;
  approvingKeyCheckpointHash: string;
  approvingDeviceKeyDirectoryProofHash: string;
  targetKeyCheckpointSequence: number;
  targetKeyCheckpointHash: string;
  umkDistributionDeliveryCommitment: StrictJsonValue;
  trustTransferDeliveryCommitment: StrictJsonValue;
  deviceApprovalKekInitialDeliveryCommitments: StrictJsonValue[];
} {
  const details = isRecord(value.surface_details) ? value.surface_details : value;
  return {
    approvedDeviceRegistrationSasHash: details.approved_device_registration_sas_hash as string,
    pendingRegistrationId: details.pending_registration_id as string,
    pendingRegistrationChallengeHash: details.pending_registration_challenge_hash as string,
    approvingOwnerKind: value.approving_owner_kind as "device",
    approvingOwnerId: value.approving_owner_id as string,
    approvingSigningKeyId: value.approving_signing_key_id as string,
    approvingKeyCheckpointSequence: value.approving_key_checkpoint_sequence as number,
    approvingKeyCheckpointHash: value.approving_key_checkpoint_hash as string,
    approvingDeviceKeyDirectoryProofHash:
      details.approving_device_key_directory_proof_hash as string,
    targetKeyCheckpointSequence: value.target_key_checkpoint_sequence as number,
    targetKeyCheckpointHash: value.target_key_checkpoint_hash as string,
    umkDistributionDeliveryCommitment:
      details.umk_distribution_delivery_commitment as StrictJsonValue,
    trustTransferDeliveryCommitment: details.trust_transfer_delivery_commitment as StrictJsonValue,
    deviceApprovalKekInitialDeliveryCommitments:
      details.device_approval_kek_initial_delivery_commitments as StrictJsonValue[],
  };
}

function targetApprovalFields(params: {
  targetDeviceId: string;
  targetDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  targetDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  targetDeviceClientNonce: string;
}): {
  targetDeviceId: string;
  targetDeviceSigningKeyId: string;
  targetDeviceHybridSigningPublicKeyMaterialHash: string;
  targetDeviceHybridEncryptionPublicKeyMaterialHash: string;
  targetDeviceEncryptionKeyId: string;
  targetDeviceClientNonceHash: string;
} {
  return {
    targetDeviceId: params.targetDeviceId,
    targetDeviceSigningKeyId: computeSigningKeyId(
      params.targetDeviceHybridSigningPublicKeyMaterial,
    ),
    targetDeviceHybridSigningPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.targetDeviceHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceHybridEncryptionPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.targetDeviceHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(
      params.targetDeviceHybridEncryptionPublicKeyMaterial,
    ),
    targetDeviceClientNonceHash: blake3Base64Url(base64UrlDecode(params.targetDeviceClientNonce)),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strictJsonEqual(left: unknown, right: StrictJsonValue): boolean {
  try {
    return canonicalizeStrict(left as StrictJsonValue) === canonicalizeStrict(right);
  } catch {
    return false;
  }
}

export async function handleTofuTrustDevice(p: HandlerPayload): Promise<unknown> {
  await trustDevice(
    {
      userId: p.userId as string,
      deviceId: p.deviceId as string,
      hybridSigningPublicKeyMaterial:
        p.hybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial,
      ecdhPublicKey: p.ecdhPublicKey as Uint8Array,
      firstSeenAt: (p.firstSeenAt as number) ?? Date.now(),
      lastSeenAt: (p.lastSeenAt as number) ?? Date.now(),
    },
    p.namespace as string | undefined,
  );
  return { status: "ok" };
}

export async function handleTofuUpdateLastSeen(p: HandlerPayload): Promise<unknown> {
  await updateDeviceLastSeen(
    p.userId as string,
    p.deviceId as string,
    p.namespace as string | undefined,
  );
  return { status: "ok" };
}

export async function handleTofuHandleResult(p: HandlerPayload): Promise<unknown> {
  await handleTofuResult(
    {
      status: p.status as Parameters<typeof handleTofuResult>[0]["status"],
      newEntry: p.newEntry as Parameters<typeof handleTofuResult>[0]["newEntry"],
    },
    p.namespace as string | undefined,
  );
  return { status: "ok" };
}

export async function handleTofuGetAllEntries(p: HandlerPayload): Promise<unknown> {
  const entries = await getAllTofuEntries(p.namespace as string | undefined);
  return {
    entries: entries.map((entry) => ({
      userId: entry.userId,
      deviceId: entry.deviceId,
      hybridSigningPublicKeyMaterial: entry.hybridSigningPublicKeyMaterial,
      ecdhPublicKey: entry.ecdhPublicKey,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
    })),
  };
}

export async function handleTofuImportEntries(p: HandlerPayload): Promise<unknown> {
  const entries = p.entries as Array<{
    userId: string;
    deviceId: string;
    hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    ecdhPublicKey: Uint8Array;
    firstSeenAt: number;
    lastSeenAt: number;
  }>;
  await importTofuEntries(entries, p.namespace as string | undefined);
  return { status: "ok" };
}
