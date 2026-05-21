import { authApi, devicesApi } from "@/shared/api";
import type { DeviceInfo } from "@/shared/api/devices";
import {
  authState,
  deviceState,
  setCryptoWorkerReady,
  setFullSession,
  setTofuErrors,
} from "@/entities/session";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker, isTofuHardFail } from "@/shared/lib/crypto/worker/client";
import { persistCurrentKeysWithDsk } from "@/shared/lib/auth/key-persistence";

export async function restoreKeysFromPassword(password: string): Promise<void> {
  const auth = authState();
  if (!auth) throw new Error("No session");

  const worker = getCryptoWorker();

  try {
    const [saltRes, meRes] = await Promise.all([authApi.getSalt(auth.user.email), authApi.me()]);
    const device = deviceState();
    const resolvedDeviceId = device?.deviceId ?? meRes.device_id ?? "";
    const hadDsk = await worker.hasStoredDsk();
    const deviceSigningKeyId = device?.deviceSigningKeyId ?? undefined;

    await worker.initFromPassword({
      password,
      salt: base64UrlDecode(saltRes.salt),
      kdfParams: saltRes.kdf_params,
      dsk: null,
      useStoredDsk: Boolean(deviceSigningKeyId),
      userId: auth.user.id,
      deviceId: resolvedDeviceId,
      ...(deviceSigningKeyId ? { deviceSigningKeyId } : {}),
      keyRestoreEndpointRef: meRes.key_restore_endpoint_ref ?? null,
    });

    if (hadDsk) {
      await persistRestoredKeysWithDsk(auth.user.id, !!meRes.remember_me);
    }

    const finalReady = await worker.isReady();
    if (!finalReady) {
      throw new Error("Key restoration failed. Please try again.");
    }

    const publicKeys = await worker.getPublicKeys();
    const identityHybridSigningPublicKeyMaterial =
      publicKeys.identityHybridSigningPublicKeyMaterial ?? null;
    const deviceHybridSigningPublicKeyMaterial =
      publicKeys.deviceHybridSigningPublicKeyMaterial ?? null;

    setFullSession(
      {
        user: auth.user,
        sessionId: auth.sessionId,
        identityHybridSigningPublicKeyMaterial,
        identityEcdhPublic: publicKeys.identityEcdhPublic,
        expiresAt: auth.expiresAt,
      },
      {
        deviceId: resolvedDeviceId,
        deviceSigningKeyId: publicKeys.deviceSigningKeyId ?? null,
        deviceHybridSigningPublicKeyMaterial,
        deviceEcdhPublic: publicKeys.deviceEcdhPublic ?? null,
      },
    );

    await verifyRestoredDeviceTrust({
      devices: resolvedDeviceId ? await listDevicesForTrustVerification(resolvedDeviceId) : [],
      resolvedDeviceId,
      userId: auth.user.id,
      hasDeviceSigningPublic: !!deviceHybridSigningPublicKeyMaterial,
    });

    await worker.clearTransientKeys();
    setCryptoWorkerReady(true);
  } finally {
    await worker.clearTransientKeys().catch(() => undefined);
  }
}

async function persistRestoredKeysWithDsk(userId: string, rememberMe: boolean): Promise<void> {
  try {
    await persistCurrentKeysWithDsk(userId, { persistUmk: rememberMe });
  } catch {
    // DSK persistence is best effort; do not add fallback key caches.
  }
}

async function listDevicesForTrustVerification(popDeviceId: string): Promise<DeviceInfo[]> {
  const { devices } = await devicesApi.list({ popDeviceId });
  return devices;
}

async function verifyRestoredDeviceTrust(params: {
  devices: DeviceInfo[];
  resolvedDeviceId: string;
  userId: string;
  hasDeviceSigningPublic: boolean;
}): Promise<void> {
  if (!params.resolvedDeviceId || !params.hasDeviceSigningPublic) {
    return;
  }

  const worker = getCryptoWorker();

  try {
    const { errors } = await worker.tofuVerifyAllDevices({
      devices: params.devices.map((device) => ({
        name: device.name,
        userId: params.userId,
        deviceId: device.id,
        ecdhPublicKey: base64UrlDecode(device.hybrid_encryption_public_key_material.x25519_public),
        deviceHybridSigningPublicKeyMaterial: device.hybrid_signing_public_key_material,
        deviceHybridEncryptionPublicKeyMaterial: device.hybrid_encryption_public_key_material,
        identitySignature: device.approval_signature,
        identitySignaturePurpose: device.approval_signature_surface,
        identitySignatureContext: device.approval_proof,
        approvalDeliveryCommitments: device.approval_delivery_commitments,
        approvalDeliveryArtifacts: device.approval_delivery_artifacts,
        clientNonce: device.client_nonce,
      })),
    });
    setTofuErrors(errors);
  } catch (error) {
    if (isTofuHardFail(error)) {
      throw error;
    }
  }
}
