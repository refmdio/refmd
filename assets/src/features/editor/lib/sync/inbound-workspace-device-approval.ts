import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getTofuEntry } from "@/shared/lib/crypto/trust-store";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type {
  ShareVerificationParticipantDevice,
  ShareVerificationWorkspaceDevice,
} from "../../model/document-state/access";
import { recordSyncPerf } from "./perf";

export async function verifyWorkspaceDirectoryDeviceIdentity(
  device: ShareVerificationWorkspaceDevice,
  worker: ReturnType<typeof getCryptoWorker>,
  options: {
    namespace?: string;
    allowFirstSeenIdentity?: boolean;
    deferTofuPersistence?: boolean;
    approvalSigningKeys?: ReadonlyMap<string, HybridSigningPublicKeyMaterial>;
  } = {},
): Promise<boolean> {
  return verifyIdentitySignedWorkspaceDevice(
    {
      userId: device.user_id,
      deviceId: device.device_id,
      deviceHybridSigningPublicKeyMaterial: device.hybrid_signing_public_key_material,
      deviceHybridEncryptionPublicKeyMaterial: device.hybrid_encryption_public_key_material,
      deviceEcdhPublicKey: device.hybrid_encryption_public_key_material.x25519_public,
      identityHybridSigningPublicKeyMaterial: device.identity_hybrid_signing_public_key_material,
      identityEcdhPublicKey: device.identity_hybrid_encryption_public_key_material.x25519_public,
      identityHybridSignature: device.approval_signature,
      identitySignaturePurpose: device.approval_signature_surface,
      identitySignatureContext: device.approval_proof,
      approvalDeliveryCommitments: device.approval_delivery_commitments,
      approvalDeliveryArtifacts: device.approval_delivery_artifacts,
      clientNonce: device.client_nonce,
    },
    worker,
    options,
  );
}

export async function verifyMountedWorkspaceDirectoryDeviceIdentity(
  device: ShareVerificationParticipantDevice,
  worker: ReturnType<typeof getCryptoWorker>,
  options: {
    namespace?: string;
    allowFirstSeenIdentity?: boolean;
    deferTofuPersistence?: boolean;
    approvalSigningKeys?: ReadonlyMap<string, HybridSigningPublicKeyMaterial>;
  } = {},
): Promise<boolean> {
  if (
    !device.identity_hybrid_signing_public_key_material ||
    !device.identity_hybrid_encryption_public_key_material ||
    device.approval_signature === undefined ||
    !device.approval_signature_surface ||
    !device.approval_proof ||
    !device.client_nonce ||
    !device.hybrid_encryption_public_key_material
  ) {
    return true;
  }

  return verifyIdentitySignedWorkspaceDevice(
    {
      userId: device.principal_id,
      deviceId: device.device_id,
      deviceHybridSigningPublicKeyMaterial: device.hybrid_signing_public_key_material,
      deviceHybridEncryptionPublicKeyMaterial: device.hybrid_encryption_public_key_material,
      deviceEcdhPublicKey: device.hybrid_encryption_public_key_material.x25519_public,
      identityHybridSigningPublicKeyMaterial: device.identity_hybrid_signing_public_key_material,
      identityEcdhPublicKey: device.identity_hybrid_encryption_public_key_material.x25519_public,
      identityHybridSignature: device.approval_signature,
      identitySignaturePurpose: device.approval_signature_surface,
      identitySignatureContext: device.approval_proof,
      approvalDeliveryCommitments: device.approval_delivery_commitments,
      approvalDeliveryArtifacts: device.approval_delivery_artifacts,
      clientNonce: device.client_nonce,
    },
    worker,
    options,
  );
}

async function verifyIdentitySignedWorkspaceDevice(
  params: {
    userId: string;
    deviceId: string;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceHybridEncryptionPublicKeyMaterial: NonNullable<
      ShareVerificationParticipantDevice["hybrid_encryption_public_key_material"]
    >;
    deviceEcdhPublicKey: string;
    identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    identityEcdhPublicKey: string;
    identityHybridSignature: unknown;
    identitySignaturePurpose: string;
    identitySignatureContext: Record<string, unknown>;
    approvalDeliveryCommitments?: Record<string, unknown> | null;
    approvalDeliveryArtifacts?: Record<string, unknown> | null;
    clientNonce: string;
  },
  worker: ReturnType<typeof getCryptoWorker>,
  options: {
    namespace?: string;
    allowFirstSeenIdentity?: boolean;
    deferTofuPersistence?: boolean;
    approvalSigningKeys?: ReadonlyMap<string, HybridSigningPublicKeyMaterial>;
  } = {},
): Promise<boolean> {
  if (
    params.identityHybridSigningPublicKeyMaterial.owner_kind !== "identity" ||
    params.identityHybridSigningPublicKeyMaterial.owner_id !== params.userId ||
    params.deviceHybridSigningPublicKeyMaterial.owner_kind !== "device" ||
    params.deviceHybridSigningPublicKeyMaterial.owner_id !== params.deviceId
  ) {
    recordWorkspaceDeviceIdentityRejected(params, "owner_mismatch", {
      identityOwnerKind: params.identityHybridSigningPublicKeyMaterial.owner_kind,
      identityOwnerId: params.identityHybridSigningPublicKeyMaterial.owner_id,
      deviceOwnerKind: params.deviceHybridSigningPublicKeyMaterial.owner_kind,
      deviceOwnerId: params.deviceHybridSigningPublicKeyMaterial.owner_id,
    });
    return true;
  }

  const identityEcdhPk = base64UrlDecode(params.identityEcdhPublicKey);
  const identityTofuResult = await worker.tofuVerify({
    userId: params.userId,
    deviceId: params.userId,
    hybridSigningPublicKeyMaterial: params.identityHybridSigningPublicKeyMaterial,
    ecdhPublicKey: identityEcdhPk,
    ...(options.namespace ? { namespace: options.namespace } : {}),
  });

  if (
    identityTofuResult.status === "identity_key_changed" ||
    identityTofuResult.status === "ecdh_key_mismatch"
  ) {
    recordWorkspaceDeviceIdentityRejected(params, "identity_tofu_changed", {
      tofuStatus: identityTofuResult.status,
    });
    return true;
  }

  if (identityTofuResult.status === "first_seen" && !options.allowFirstSeenIdentity) {
    recordWorkspaceDeviceIdentityRejected(params, "identity_first_seen_unpinned");
    return true;
  }

  const approvalHybridSigningPublicKeyMaterial =
    await resolveApprovalHybridSigningPublicKeyMaterial({
      userId: params.userId,
      purpose: params.identitySignaturePurpose,
      proof: params.identitySignatureContext,
      namespace: options.namespace,
      approvalSigningKeys: options.approvalSigningKeys,
    });
  if (
    params.identitySignaturePurpose === "device_approval" &&
    !approvalHybridSigningPublicKeyMaterial
  ) {
    recordWorkspaceDeviceIdentityRejected(params, "approval_signing_key_missing", {
      approvingOwnerId:
        typeof params.identitySignatureContext.approving_owner_id === "string"
          ? params.identitySignatureContext.approving_owner_id
          : null,
      approvingSigningKeyId:
        typeof params.identitySignatureContext.approving_signing_key_id === "string"
          ? params.identitySignatureContext.approving_signing_key_id
          : null,
      ...describeApprovalSigningKeyLookup(
        params.identitySignatureContext,
        options.approvalSigningKeys,
      ),
    });
    return true;
  }
  const verificationParams = {
    deviceId: params.deviceId,
    deviceHybridSigningPublicKeyMaterial: params.deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: params.deviceHybridEncryptionPublicKeyMaterial,
    deviceEcdhPublic: base64UrlDecode(params.deviceEcdhPublicKey),
    clientNonce: base64UrlDecode(params.clientNonce),
    identitySignature: params.identityHybridSignature,
    identityHybridSigningPublicKeyMaterial: params.identityHybridSigningPublicKeyMaterial,
    ...(approvalHybridSigningPublicKeyMaterial ? { approvalHybridSigningPublicKeyMaterial } : {}),
    identitySignatureContext: params.identitySignatureContext,
    approvalDeliveryCommitments: params.approvalDeliveryCommitments,
    approvalDeliveryArtifacts: params.approvalDeliveryArtifacts,
  };
  const valid =
    params.identitySignaturePurpose === "genesis_device_bootstrap"
      ? await worker.verifyGenesisDeviceBootstrapSignature(verificationParams)
      : params.identitySignaturePurpose === "device_approval"
        ? await worker.verifyDeviceApprovalSignature(verificationParams)
        : params.identitySignaturePurpose === "recovery_device_approval"
          ? await worker.verifyRecoveryDeviceApprovalSignature(verificationParams)
          : false;

  if (!valid) {
    recordWorkspaceDeviceIdentityRejected(params, "approval_signature_invalid");
    return true;
  }

  const persist =
    identityTofuResult.status === "first_seen"
      ? worker.tofuTrustDevice({
          userId: params.userId,
          deviceId: params.userId,
          hybridSigningPublicKeyMaterial: params.identityHybridSigningPublicKeyMaterial,
          ecdhPublicKey: identityEcdhPk,
          ...(options.namespace ? { namespace: options.namespace } : {}),
        })
      : worker.tofuUpdateLastSeen({
          userId: params.userId,
          deviceId: params.userId,
          ...(options.namespace ? { namespace: options.namespace } : {}),
        });

  if (options.deferTofuPersistence) {
    void persist.catch(() => {});
  } else {
    await persist;
  }

  return false;
}

function recordWorkspaceDeviceIdentityRejected(
  params: {
    userId: string;
    deviceId: string;
    identitySignaturePurpose: string;
  },
  reason: string,
  detail: Record<string, unknown> = {},
): void {
  recordSyncPerf("workspace_directory_identity_rejected", {
    userId: params.userId,
    deviceId: params.deviceId,
    purpose: params.identitySignaturePurpose,
    reason,
    ...detail,
  });
}

function describeApprovalSigningKeyLookup(
  proof: Record<string, unknown>,
  approvalSigningKeys?: ReadonlyMap<string, HybridSigningPublicKeyMaterial>,
): Record<string, unknown> {
  if (
    typeof proof.approving_signing_key_id !== "string" ||
    typeof proof.approving_owner_id !== "string"
  ) {
    return { approvalSigningKeyCount: approvalSigningKeys?.size ?? 0 };
  }

  const candidate = approvalSigningKeys?.get(proof.approving_signing_key_id);
  if (!candidate) {
    return {
      approvalSigningKeyCount: approvalSigningKeys?.size ?? 0,
      hasApprovalSigningKeyCandidate: false,
    };
  }

  return {
    approvalSigningKeyCount: approvalSigningKeys?.size ?? 0,
    hasApprovalSigningKeyCandidate: true,
    approvalSigningKeyCandidateOwnerKind: candidate.owner_kind,
    approvalSigningKeyCandidateOwnerId: candidate.owner_id,
    approvalSigningKeyCandidateKeyMatches:
      computeSigningKeyId(candidate) === proof.approving_signing_key_id,
  };
}

async function resolveApprovalHybridSigningPublicKeyMaterial(params: {
  userId: string;
  purpose: string;
  proof: Record<string, unknown>;
  namespace?: string;
  approvalSigningKeys?: ReadonlyMap<string, HybridSigningPublicKeyMaterial>;
}): Promise<HybridSigningPublicKeyMaterial | null> {
  if (params.purpose !== "device_approval") return null;
  if (
    params.proof.approving_owner_kind !== "device" ||
    typeof params.proof.approving_owner_id !== "string" ||
    typeof params.proof.approving_signing_key_id !== "string"
  ) {
    return null;
  }

  const directoryMaterial = params.approvalSigningKeys?.get(params.proof.approving_signing_key_id);
  if (
    directoryMaterial?.owner_kind === "device" &&
    directoryMaterial.owner_id === params.proof.approving_owner_id &&
    computeSigningKeyId(directoryMaterial) === params.proof.approving_signing_key_id
  ) {
    return directoryMaterial;
  }

  const approver = await getTofuEntry(
    params.userId,
    params.proof.approving_owner_id,
    params.namespace,
  );
  const material = approver?.hybridSigningPublicKeyMaterial ?? null;
  if (!material) return null;

  return computeSigningKeyId(material) === params.proof.approving_signing_key_id ? material : null;
}
