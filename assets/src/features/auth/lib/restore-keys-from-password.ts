import { authApi, devicesApi } from "@/shared/api";
import type { DeviceInfo } from "@/shared/api/devices";
import {
  authState,
  deviceState,
  setCryptoWorkerReady,
  setFullSession,
  setTofuErrors,
} from "@/entities/session";
import { loadDskInitData, storeWrappedDeviceKeysRaw } from "@/shared/lib/crypto/dsk";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker, isTofuHardFail } from "@/shared/lib/crypto/worker/client";
import {
  persistPdkWrappedKeys,
  persistWrappedUmk,
  readPdkBlobs,
} from "@/shared/lib/auth/key-persistence";
import type { InitPdkResult } from "@/shared/lib/crypto/worker/types";

export async function restoreKeysFromPassword(password: string): Promise<void> {
  const auth = authState();
  if (!auth) throw new Error("No session");

  const worker = getCryptoWorker();

  try {
    const [saltRes, meRes] = await Promise.all([authApi.getSalt(auth.user.email), authApi.me()]);
    const device = deviceState();
    const resolvedDeviceId = device?.deviceId ?? meRes.device_id ?? "";
    const dskData = await loadDskInitData();
    const hadDsk = dskData?.dsk != null;
    const persistedPdkBlobs = readPdkBlobs();
    const pdkBlobs =
      persistedPdkBlobs.pdkWrappedUmk &&
      persistedPdkBlobs.pdkWrappedDeviceEcdh &&
      persistedPdkBlobs.pdkWrappedDeviceSigning
        ? {
            pdkWrappedUmk: persistedPdkBlobs.pdkWrappedUmk,
            pdkWrappedDeviceEcdh: persistedPdkBlobs.pdkWrappedDeviceEcdh,
            pdkWrappedDeviceSigning: persistedPdkBlobs.pdkWrappedDeviceSigning,
          }
        : {};

    const initResult = await worker.initFromPassword({
      password,
      salt: base64UrlDecode(saltRes.salt),
      kdfParams: saltRes.kdf_params,
      dsk: dskData?.dsk ?? null,
      wrappedDeviceEcdh: dskData?.wrappedDeviceEcdh ?? undefined,
      wrappedDeviceSigning: dskData?.wrappedDeviceSigning ?? undefined,
      serverEncryptedUmk: meRes.keys?.encrypted_umk
        ? base64UrlDecode(meRes.keys.encrypted_umk)
        : undefined,
      serverUmkNonce: meRes.keys?.umk_nonce ? base64UrlDecode(meRes.keys.umk_nonce) : undefined,
      userId: auth.user.id,
      deviceId: resolvedDeviceId,
      encryptedIdentityEcdh: meRes.keys?.encrypted_ecdh_private
        ? base64UrlDecode(meRes.keys.encrypted_ecdh_private)
        : undefined,
      identityEcdhNonce: meRes.keys?.encrypted_ecdh_private_nonce
        ? base64UrlDecode(meRes.keys.encrypted_ecdh_private_nonce)
        : undefined,
      encryptedIdentitySigning: meRes.keys?.encrypted_signing_private
        ? base64UrlDecode(meRes.keys.encrypted_signing_private)
        : undefined,
      identitySigningNonce: meRes.keys?.encrypted_signing_private_nonce
        ? base64UrlDecode(meRes.keys.encrypted_signing_private_nonce)
        : undefined,
      ...pdkBlobs,
      returnPdkWrapped: !hadDsk,
    });

    if (hadDsk) {
      await persistRestoredKeysWithDsk(auth.user.id, !!meRes.remember_me, {
        password,
        salt: base64UrlDecode(saltRes.salt),
        kdfParams: saltRes.kdf_params,
      });
    } else if (initResult.pdkWrapped) {
      persistRestoredKeysWithPdk(initResult.pdkWrapped);
    }

    const finalReady = await worker.isReady();
    if (!finalReady) {
      throw new Error("Key restoration failed. Please try again.");
    }

    const publicKeys = await worker.getPublicKeys();

    setFullSession(
      {
        user: auth.user,
        sessionId: auth.sessionId,
        identitySigningPublic: publicKeys.identitySigningPublic,
        identityEcdhPublic: publicKeys.identityEcdhPublic,
        expiresAt: auth.expiresAt,
      },
      {
        deviceId: resolvedDeviceId,
        deviceSigningPublic: publicKeys.deviceSigningPublic ?? null,
        deviceEcdhPublic: publicKeys.deviceEcdhPublic ?? null,
      },
    );

    await verifyRestoredDeviceTrust({
      devices: resolvedDeviceId ? await listDevicesForTrustVerification(resolvedDeviceId) : [],
      resolvedDeviceId,
      userId: auth.user.id,
      hasDeviceSigningPublic: !!publicKeys.deviceSigningPublic,
    });

    await worker.clearTransientKeys();
    setCryptoWorkerReady(true);
  } finally {
    await worker.clearTransientKeys().catch(() => undefined);
  }
}

async function persistRestoredKeysWithDsk(
  userId: string,
  rememberMe: boolean,
  passwordParams: {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  },
): Promise<void> {
  const worker = getCryptoWorker();

  try {
    const wrappedUmk = await worker.wrapUmkWithDsk(userId);
    await persistWrappedUmk({ wrappedUmk, kmsi: rememberMe, userId });

    const wrappedDeviceKeys = await worker.wrapDeviceKeysWithDsk(userId);
    await storeWrappedDeviceKeysRaw(
      wrappedDeviceKeys.wrappedEcdh,
      wrappedDeviceKeys.wrappedSigning,
    );
  } catch {
    try {
      const pdkWrapped = await worker.wrapWithPdk({ passwordParams });
      persistPdkWrappedKeys(pdkWrapped);
    } catch {
      // PDK fallback also failed
    }
  }
}

function persistRestoredKeysWithPdk(pdkWrapped: InitPdkResult): void {
  persistPdkWrappedKeys(pdkWrapped);
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
        signingPublicKey: base64UrlDecode(device.signing_public_key),
        ecdhPublicKey: base64UrlDecode(device.ecdh_public_key),
        identitySignature: device.identity_signature ?? null,
        clientNonce: device.client_nonce ?? null,
      })),
    });
    setTofuErrors(errors);
  } catch (error) {
    if (isTofuHardFail(error)) {
      throw error;
    }
  }
}
