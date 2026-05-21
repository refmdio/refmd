import type { DeviceInfo } from "@/shared/api/devices";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { applyTofuVerification } from "@/shared/lib/crypto/tofu-status";
interface DeviceTofuVerificationResult {
  hardFailMessage: string | null;
  warnings: string[];
}
export async function verifyDeviceListTofu(params: {
  devices: DeviceInfo[];
  userId: string;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
}): Promise<DeviceTofuVerificationResult> {
  const worker = getCryptoWorker();
  const warnings: string[] = [];
  for (const device of params.devices) {
    if (!device.hybrid_signing_public_key_material) {
      continue;
    }
    try {
      const deviceHybridSigningPublicKeyMaterial =
        device.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
      const ecdhPublicKey = base64UrlDecode(
        device.hybrid_encryption_public_key_material.x25519_public,
      );
      const tofuResult = await worker.tofuVerify({
        userId: params.userId,
        deviceId: device.id,
        hybridSigningPublicKeyMaterial: deviceHybridSigningPublicKeyMaterial,
        ecdhPublicKey,
      });
      if (tofuResult.status === "identity_key_changed") {
        return {
          hardFailMessage: `${device.name}: Identity key changed — possible key compromise`,
          warnings,
        };
      }
      if (tofuResult.status === "ecdh_key_mismatch") {
        return {
          hardFailMessage: `${device.name}: ECDH key mismatch — possible key compromise`,
          warnings,
        };
      }
      const signatureWarning = await verifyDeviceApprovalSurface({
        device,
        ecdhPublicKey,
        identityHybridSigningPublicKeyMaterial: params.identityHybridSigningPublicKeyMaterial,
      });
      if (signatureWarning) {
        warnings.push(signatureWarning);
        continue;
      }
      await applyTofuVerification(
        {
          userId: params.userId,
          deviceId: device.id,
          hybridSigningPublicKeyMaterial: deviceHybridSigningPublicKeyMaterial,
          ecdhPublicKey,
        },
        tofuResult,
      );
    } catch {
      // Treat per-device verifier failures as warnings so the rest of the device list can still be checked.
      warnings.push(`${device.name}: Key verification unavailable`);
    }
  }
  return {
    hardFailMessage: null,
    warnings,
  };
}
async function verifyDeviceApprovalSurface(params: {
  device: DeviceInfo;
  ecdhPublicKey: Uint8Array;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
}): Promise<string | null> {
  const { device, identityHybridSigningPublicKeyMaterial, ecdhPublicKey } = params;
  if (!device.approval_signature || !device.client_nonce) {
    return `${device.name}: Missing identity signature — device approval cannot be verified`;
  }
  if (!identityHybridSigningPublicKeyMaterial) {
    return `${device.name}: Identity key unavailable — device approval cannot be verified`;
  }
  const worker = getCryptoWorker();
  const verificationParams = {
    deviceId: device.id,
    deviceHybridSigningPublicKeyMaterial:
      device.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial:
      device.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
    deviceEcdhPublic: ecdhPublicKey,
    clientNonce: base64UrlDecode(device.client_nonce),
    identitySignature: device.approval_signature,
    identitySignatureContext: device.approval_proof as Record<string, unknown>,
    approvalDeliveryCommitments: device.approval_delivery_commitments,
    approvalDeliveryArtifacts: device.approval_delivery_artifacts,
  };
  const isValid =
    device.approval_signature_surface === "genesis_device_bootstrap"
      ? await worker.verifyGenesisDeviceBootstrapSignature(verificationParams)
      : device.approval_signature_surface === "device_approval"
        ? await worker.verifyDeviceApprovalSignature(verificationParams)
        : device.approval_signature_surface === "recovery_device_approval"
          ? await worker.verifyRecoveryDeviceApprovalSignature(verificationParams)
          : false;
  if (!isValid) {
    return `${device.name}: Invalid identity signature — device approval not verified`;
  }
  return null;
}
