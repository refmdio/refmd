import { x25519 } from "@noble/curves/ed25519.js";
import { encryptionApi, ApiError } from "@/shared/api";
import {
  base64UrlEncode,
  base64UrlDecode,
  decryptKekFromDeviceEnvelope,
  decryptKekFromMemberEnvelope,
  unwrapKekFromBackup,
  encryptKekForDevice,
  wrapKekWithUmk,
  verifyTofu,
  handleTofuResult,
} from "@/shared/lib/crypto";
import type { IdentityKeyPair } from "@/shared/lib/crypto";

interface ResolvedKek {
  kek: Uint8Array;
  kekVersion: number;
}

interface AuthParams {
  user: { id: string };
  umk: Uint8Array;
  identityKeys: IdentityKeyPair;
}

interface DeviceParams {
  deviceId: string;
  deviceEcdhPrivate: Uint8Array;
}

const KEK_CACHE_TTL_MS = 5 * 60 * 1000;
const kekCache = new Map<string, { kek: Uint8Array; kekVersion: number; resolvedAt: number }>();

export function getCachedKek(workspaceId: string): ResolvedKek | null {
  const cached = kekCache.get(workspaceId);
  if (!cached) return null;
  return { kek: cached.kek, kekVersion: cached.kekVersion };
}

export function clearKekCache(workspaceId?: string): void {
  if (workspaceId) {
    kekCache.delete(workspaceId);
  } else {
    kekCache.clear();
  }
}

export async function resolveActiveKek(
  workspaceId: string,
  auth: AuthParams,
  device: DeviceParams,
): Promise<ResolvedKek> {
  const cached = kekCache.get(workspaceId);
  if (cached && Date.now() - cached.resolvedAt < KEK_CACHE_TTL_MS) {
    return { kek: cached.kek, kekVersion: cached.kekVersion };
  }

  let keys: Awaited<ReturnType<typeof encryptionApi.getWorkspaceKeysWithPop>>["keys"] = [];
  let currentKekVersion = 0;

  try {
    const keysResponse = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, device.deviceId);
    keys = keysResponse.keys;
    currentKekVersion = keysResponse.current_kek_version;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      const details = (e.body as Record<string, unknown>)?.details as
        | Record<string, unknown>
        | undefined;
      currentKekVersion = (details?.current_kek_version as number) ?? 0;
    } else {
      throw e;
    }
  }

  if (currentKekVersion === 0) {
    throw new Error("Encryption not set up for this workspace");
  }

  const activeKey = keys.find((k) => k.key_version === currentKekVersion);
  let kek: Uint8Array;

  if (activeKey && activeKey.sender_ecdh_public_key && activeKey.sender_signing_public_key) {
    const senderSigningPk = base64UrlDecode(activeKey.sender_signing_public_key);
    const senderEcdhPk = base64UrlDecode(activeKey.sender_ecdh_public_key);

    const tofuResult = await verifyTofu(
      auth.user.id,
      activeKey.sender_device_id,
      senderSigningPk,
      senderEcdhPk,
    );
    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      throw new Error("Key verification failed for KEK sender device.");
    }
    await handleTofuResult(tofuResult);

    kek = decryptKekFromDeviceEnvelope(
      base64UrlDecode(activeKey.encrypted_kek),
      base64UrlDecode(activeKey.nonce),
      device.deviceEcdhPrivate,
      senderEcdhPk,
      workspaceId,
      auth.user.id,
      activeKey.sender_device_id,
      device.deviceId,
      currentKekVersion,
    );

    (async () => {
      try {
        await encryptionApi.getKekBackupWithPop(workspaceId);
      } catch {
        try {
          const backup = wrapKekWithUmk(
            kek,
            auth.umk,
            workspaceId,
            auth.user.id,
            currentKekVersion,
          );
          await encryptionApi.createKekBackupWithPop(workspaceId, {
            key_version: currentKekVersion,
            encrypted_kek: base64UrlEncode(backup.encryptedKek),
            nonce: base64UrlEncode(backup.nonce),
          });
        } catch {
          /* fire-and-forget */
        }
      }
    })();
  } else {
    const envelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
    if (envelope && envelope.sender_ecdh_public_key && envelope.sender_signing_public_key) {
      const meSenderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
      const meSenderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);

      const meTofuResult = await verifyTofu(
        envelope.sender_user_id,
        envelope.sender_device_id,
        meSenderSigningPk,
        meSenderEcdhPk,
      );
      if (
        meTofuResult.status === "identity_key_changed" ||
        meTofuResult.status === "ecdh_key_mismatch"
      ) {
        throw new Error("Key verification failed for member envelope sender.");
      }
      await handleTofuResult(meTofuResult);

      kek = decryptKekFromMemberEnvelope(
        base64UrlDecode(envelope.encrypted_kek),
        base64UrlDecode(envelope.nonce),
        auth.identityKeys.ecdhPrivate,
        meSenderEcdhPk,
        workspaceId,
        auth.user.id,
        envelope.key_version,
        envelope.sender_device_id,
      );

      const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
      const deviceEnvelope = encryptKekForDevice(
        kek,
        device.deviceEcdhPrivate,
        deviceEcdhPublic,
        workspaceId,
        auth.user.id,
        device.deviceId,
        device.deviceId,
        currentKekVersion,
      );
      try {
        await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
          device_id: device.deviceId,
          sender_device_id: device.deviceId,
          key_version: currentKekVersion,
          encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
          nonce: base64UrlEncode(deviceEnvelope.nonce),
        });
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 409)) throw e;
      }

      const umkBackup = wrapKekWithUmk(kek, auth.umk, workspaceId, auth.user.id, currentKekVersion);
      try {
        await encryptionApi.createKekBackupWithPop(workspaceId, {
          key_version: currentKekVersion,
          encrypted_kek: base64UrlEncode(umkBackup.encryptedKek),
          nonce: base64UrlEncode(umkBackup.nonce),
        });
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 409)) throw e;
      }
    } else {
      let backupData: { encrypted_kek: string; nonce: string; key_version: number };
      try {
        backupData = await encryptionApi.getKekBackupWithPop(workspaceId);
      } catch {
        throw new Error(
          "KEK recovery not available. No device envelope, member envelope, or UMK backup found.",
        );
      }

      kek = unwrapKekFromBackup(
        base64UrlDecode(backupData.encrypted_kek),
        base64UrlDecode(backupData.nonce),
        auth.umk,
        workspaceId,
        auth.user.id,
        backupData.key_version,
      );

      const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
      const deviceEnvelope = encryptKekForDevice(
        kek,
        device.deviceEcdhPrivate,
        deviceEcdhPublic,
        workspaceId,
        auth.user.id,
        device.deviceId,
        device.deviceId,
        currentKekVersion,
      );
      try {
        await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
          device_id: device.deviceId,
          sender_device_id: device.deviceId,
          key_version: currentKekVersion,
          encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
          nonce: base64UrlEncode(deviceEnvelope.nonce),
        });
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 409)) throw e;
      }
    }
  }

  kekCache.set(workspaceId, { kek, kekVersion: currentKekVersion, resolvedAt: Date.now() });
  return { kek, kekVersion: currentKekVersion };
}
