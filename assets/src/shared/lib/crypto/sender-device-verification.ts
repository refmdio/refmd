import { base64UrlDecode, constantTimeEqual } from "./encoding";
import type { HybridEncryptionPublicKeyMaterial } from "./hybrid-encryption";
import { canonicalizeStrict, type StrictJsonValue } from "./jcs";
import { computeSigningKeyId } from "./signature";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";
import { getTofuEntry } from "./trust-store";
import { getCryptoWorker } from "./worker/client";

export interface VerifiedSenderDeviceKeys {
  ecdhPublicKey: Uint8Array;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}

export interface SignedSenderDeviceIdentity {
  sender_device_id: string;
  sender_user_id?: string;
  sender_hybrid_encryption_public_key_material?: unknown;
  sender_hybrid_signing_public_key_material?: unknown;
  sender_identity_hybrid_encryption_public_key_material?: unknown;
  sender_identity_hybrid_signing_public_key_material?: unknown;
  sender_approval_signature?: unknown;
  sender_approval_signature_surface?: string;
  sender_approval_proof?: Record<string, unknown>;
  sender_approval_delivery_commitments?: Record<string, unknown> | null;
  sender_approval_delivery_artifacts?: Record<string, unknown> | null;
  sender_client_nonce?: string;
}

export async function verifySenderDeviceIdentityAndTofu(params: {
  sender: SignedSenderDeviceIdentity;
  senderUserId: string;
  expectedIdentityHybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial | null;
  expectedIdentityEcdhPublic?: Uint8Array | null;
  allowFirstSeenIdentity?: boolean;
}): Promise<VerifiedSenderDeviceKeys> {
  const {
    sender_device_id: senderDeviceId,
    sender_hybrid_encryption_public_key_material: senderDeviceEncryptionMaterial,
    sender_hybrid_signing_public_key_material: senderDeviceMaterial,
    sender_identity_hybrid_encryption_public_key_material: senderIdentityEncryptionMaterial,
    sender_identity_hybrid_signing_public_key_material: senderIdentityMaterial,
    sender_approval_signature: senderIdentitySignature,
    sender_approval_signature_surface: senderIdentitySignaturePurpose,
    sender_approval_proof: senderIdentitySignatureContext,
    sender_approval_delivery_commitments: senderApprovalDeliveryCommitments,
    sender_approval_delivery_artifacts: senderApprovalDeliveryArtifacts,
    sender_client_nonce: senderClientNonce,
  } = params.sender;

  if (
    !senderDeviceId ||
    params.sender.sender_user_id !== params.senderUserId ||
    !senderDeviceEncryptionMaterial ||
    !senderDeviceMaterial ||
    !senderIdentityEncryptionMaterial ||
    !senderIdentityMaterial ||
    !senderIdentitySignature ||
    !senderIdentitySignaturePurpose ||
    !senderIdentitySignatureContext ||
    !senderClientNonce
  ) {
    throw new Error("sender_device_identity_metadata_missing");
  }

  const worker = getCryptoWorker();
  const deviceMaterial = senderDeviceMaterial as HybridSigningPublicKeyMaterial;
  const deviceHybridEncryptionMaterial =
    senderDeviceEncryptionMaterial as HybridEncryptionPublicKeyMaterial;
  const identityMaterial = senderIdentityMaterial as HybridSigningPublicKeyMaterial;
  const identityHybridEncryptionMaterial =
    senderIdentityEncryptionMaterial as HybridEncryptionPublicKeyMaterial;
  const ecdhPublicKey = base64UrlDecode(deviceHybridEncryptionMaterial.x25519_public);
  const identityEcdhPublicKey = base64UrlDecode(identityHybridEncryptionMaterial.x25519_public);

  if (
    identityMaterial.owner_kind !== "identity" ||
    identityMaterial.owner_id !== params.senderUserId ||
    identityHybridEncryptionMaterial.owner_kind !== "identity" ||
    identityHybridEncryptionMaterial.owner_id !== params.senderUserId ||
    deviceMaterial.owner_kind !== "device" ||
    deviceMaterial.owner_id !== senderDeviceId ||
    deviceHybridEncryptionMaterial.owner_kind !== "device" ||
    deviceHybridEncryptionMaterial.owner_id !== senderDeviceId
  ) {
    throw new Error("sender_device_identity_owner_mismatch");
  }

  if (params.expectedIdentityHybridSigningPublicKeyMaterial && params.expectedIdentityEcdhPublic) {
    if (
      canonicalizeStrict(
        params.expectedIdentityHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
      ) !== canonicalizeStrict(identityMaterial as unknown as StrictJsonValue) ||
      !constantTimeEqual(params.expectedIdentityEcdhPublic, identityEcdhPublicKey)
    ) {
      throw new Error("sender_identity_key_mismatch");
    }
  }

  const identityTofu = await worker.tofuVerify({
    userId: params.senderUserId,
    deviceId: params.senderUserId,
    hybridSigningPublicKeyMaterial: identityMaterial,
    ecdhPublicKey: identityEcdhPublicKey,
  });

  let shouldTrustFirstSeenIdentity = false;
  if (identityTofu.status === "first_seen") {
    if (
      !params.allowFirstSeenIdentity &&
      (!params.expectedIdentityHybridSigningPublicKeyMaterial || !params.expectedIdentityEcdhPublic)
    ) {
      throw new Error("sender_identity_key_unpinned");
    }
    shouldTrustFirstSeenIdentity = true;
  } else if (identityTofu.status !== "known_trusted") {
    throw new Error("sender_identity_key_changed");
  }

  const approvalHybridSigningPublicKeyMaterial =
    await resolveApprovalHybridSigningPublicKeyMaterial({
      senderUserId: params.senderUserId,
      purpose: senderIdentitySignaturePurpose,
      proof: senderIdentitySignatureContext,
    });

  const verificationParams = {
    deviceId: senderDeviceId,
    deviceHybridSigningPublicKeyMaterial: deviceMaterial,
    deviceHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionMaterial,
    deviceEcdhPublic: ecdhPublicKey,
    clientNonce: base64UrlDecode(senderClientNonce),
    identitySignature: senderIdentitySignature,
    identityHybridSigningPublicKeyMaterial: identityMaterial,
    ...(approvalHybridSigningPublicKeyMaterial ? { approvalHybridSigningPublicKeyMaterial } : {}),
    identitySignatureContext: senderIdentitySignatureContext,
    approvalDeliveryCommitments: senderApprovalDeliveryCommitments,
    approvalDeliveryArtifacts: senderApprovalDeliveryArtifacts,
  };
  const signatureValid =
    senderIdentitySignaturePurpose === "genesis_device_bootstrap"
      ? await worker.verifyGenesisDeviceBootstrapSignature(verificationParams)
      : senderIdentitySignaturePurpose === "device_approval"
        ? await worker.verifyDeviceApprovalSignature(verificationParams)
        : senderIdentitySignaturePurpose === "recovery_device_approval"
          ? await worker.verifyRecoveryDeviceApprovalSignature(verificationParams)
          : false;

  if (!signatureValid) {
    throw new Error("sender_device_approval_signature_invalid");
  }

  if (shouldTrustFirstSeenIdentity) {
    await worker.tofuTrustDevice({
      userId: params.senderUserId,
      deviceId: params.senderUserId,
      hybridSigningPublicKeyMaterial: identityMaterial,
      ecdhPublicKey: identityEcdhPublicKey,
    });
  } else {
    await worker.tofuUpdateLastSeen({
      userId: params.senderUserId,
      deviceId: params.senderUserId,
    });
  }

  const deviceTofu = await worker.tofuVerify({
    userId: params.senderUserId,
    deviceId: senderDeviceId,
    hybridSigningPublicKeyMaterial: deviceMaterial,
    ecdhPublicKey,
  });

  if (deviceTofu.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId: params.senderUserId,
      deviceId: senderDeviceId,
      hybridSigningPublicKeyMaterial: deviceMaterial,
      ecdhPublicKey,
    });
  } else if (deviceTofu.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: params.senderUserId,
      deviceId: senderDeviceId,
    });
  } else {
    throw new Error("sender_device_key_changed");
  }

  return { ecdhPublicKey, hybridSigningPublicKeyMaterial: deviceMaterial };
}

async function resolveApprovalHybridSigningPublicKeyMaterial(params: {
  senderUserId: string;
  purpose: string;
  proof: Record<string, unknown>;
}): Promise<HybridSigningPublicKeyMaterial | null> {
  if (params.purpose !== "device_approval") return null;
  if (
    params.proof.approving_owner_kind !== "device" ||
    typeof params.proof.approving_owner_id !== "string" ||
    typeof params.proof.approving_signing_key_id !== "string"
  ) {
    return null;
  }

  const approver = await getTofuEntry(params.senderUserId, params.proof.approving_owner_id);
  const material = approver?.hybridSigningPublicKeyMaterial ?? null;
  if (!material) return null;

  return computeSigningKeyId(material) === params.proof.approving_signing_key_id ? material : null;
}
