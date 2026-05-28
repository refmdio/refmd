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

const LOCAL_DEVICE_KEYS_UNAVAILABLE =
  "Local device keys are unavailable. Return to login and register this device again.";

export async function restoreKeysFromPassword(password: string): Promise<void> {
  const auth = authState();
  if (!auth) throw new Error("No session");

  const worker = getCryptoWorker();

  try {
    const [saltRes, meRes] = await Promise.all([authApi.getSalt(auth.user.email), authApi.me()]);
    const device = deviceState();
    const resolvedDeviceId = device?.deviceId ?? meRes.device_id ?? "";
    const hadDsk = await worker.hasStoredDsk();
    const cachedBootstrap = hadDsk ? await worker.loadAuthBootstrap().catch(() => null) : null;
    const cachedDeviceSigningKeyId =
      cachedBootstrap?.userId === auth.user.id && cachedBootstrap.deviceId === resolvedDeviceId
        ? cachedBootstrap.deviceSigningKeyId
        : undefined;
    const deviceSigningKeyId = device?.deviceSigningKeyId ?? cachedDeviceSigningKeyId;

    try {
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
    } catch (error) {
      if (isLocalDeviceKeyRestoreError(error)) {
        throw new Error(LOCAL_DEVICE_KEYS_UNAVAILABLE);
      }
      throw error;
    }

    if (hadDsk) {
      await persistRestoredKeysWithDsk(auth.user.id, !!meRes.remember_me);
    }

    const finalReady = await worker.isReady();
    if (!finalReady) {
      throw new Error(LOCAL_DEVICE_KEYS_UNAVAILABLE);
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
        deviceKeyCheckpointSequence: meRes.device_key_checkpoint_sequence ?? null,
        deviceKeyCheckpointHash: meRes.device_key_checkpoint_hash ?? null,
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

function isLocalDeviceKeyRestoreError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.message.startsWith("device_") || error.message === "dsk_not_available";
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
