import type { DeviceInfo } from "@/shared/api/devices";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { applyTofuVerification } from "@/shared/lib/crypto/tofu-status";
interface DeviceTofuVerificationResult {
  hardFailMessage: string | null;
  warnings: string[];
}
export async function verifyDeviceListTofu(params: {
  devices: DeviceInfo[];
  userId: string;
  identitySigningPublic: Uint8Array | null;
}): Promise<DeviceTofuVerificationResult> {
  const worker = getCryptoWorker();
  const warnings: string[] = [];
  for (const device of params.devices) {
    if (!device.signing_public_key || !device.ecdh_public_key) {
      continue;
    }
    try {
      const signingPublicKey = base64UrlDecode(device.signing_public_key);
      const ecdhPublicKey = base64UrlDecode(device.ecdh_public_key);
      const tofuResult = await worker.tofuVerify({
        userId: params.userId,
        deviceId: device.id,
        signingPublicKey,
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
      const signatureWarning = await verifyDeviceIdentitySignature({
        device,
        signingPublicKey,
        ecdhPublicKey,
        identitySigningPublic: params.identitySigningPublic,
      });
      if (signatureWarning) {
        warnings.push(signatureWarning);
        continue;
      }
      await applyTofuVerification(
        {
          userId: params.userId,
          deviceId: device.id,
          signingPublicKey,
          ecdhPublicKey,
        },
        tofuResult,
      );
    } catch {
      warnings.push(`${device.name}: Key verification unavailable`);
    }
  }
  return {
    hardFailMessage: null,
    warnings,
  };
}
async function verifyDeviceIdentitySignature(params: {
  device: DeviceInfo;
  signingPublicKey: Uint8Array;
  ecdhPublicKey: Uint8Array;
  identitySigningPublic: Uint8Array | null;
}): Promise<string | null> {
  const { device, identitySigningPublic, signingPublicKey, ecdhPublicKey } = params;
  if (!device.identity_signature || !device.client_nonce) {
    return `${device.name}: Missing identity signature — device approval cannot be verified`;
  }
  if (!identitySigningPublic) {
    return null;
  }
  const worker = getCryptoWorker();
  const isValid = await worker.verifyDeviceIdentitySignature({
    deviceId: device.id,
    deviceSigningPublic: signingPublicKey,
    deviceEcdhPublic: ecdhPublicKey,
    clientNonce: base64UrlDecode(device.client_nonce),
    identitySignature: base64UrlDecode(device.identity_signature),
    identitySigningPublic,
  });
  if (!isValid) {
    return `${device.name}: Invalid identity signature — device approval not verified`;
  }
  return null;
}
