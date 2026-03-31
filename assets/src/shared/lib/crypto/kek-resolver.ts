import { encryptionApi, ApiError } from "@/shared/api";
import { base64UrlEncode, base64UrlDecode } from "./encoding";
import { getCryptoWorker } from "./worker/client";
import { authState, deviceState } from "@/shared/lib/auth-state";

const pendingActiveKekResolutions = new Map<string, Promise<{ kekVersion: number }>>();

export async function resolveActiveKek(
  workspaceId: string,
  signal?: AbortSignal,
): Promise<{ kekVersion: number }> {
  const worker = getCryptoWorker();
  const auth = authState();
  const device = deviceState();
  if (!auth || !device?.deviceId) throw new Error("Not authenticated");

  const cached = await worker.resolveKek(workspaceId);
  if (cached.found && cached.keyVersion !== undefined) {
    await worker.setActiveKekVersion(workspaceId, cached.keyVersion);
    return { kekVersion: cached.keyVersion };
  }

  const pending = pendingActiveKekResolutions.get(workspaceId);
  if (pending) return pending;

  const resolution = doResolveActiveKek(workspaceId, auth.user.id, device.deviceId, worker, signal);
  pendingActiveKekResolutions.set(workspaceId, resolution);

  try {
    return await resolution;
  } finally {
    pendingActiveKekResolutions.delete(workspaceId);
  }
}

async function doResolveActiveKek(
  workspaceId: string,
  userId: string,
  deviceId: string,
  worker: ReturnType<typeof getCryptoWorker>,
  signal?: AbortSignal,
): Promise<{ kekVersion: number }> {
  const device = deviceState();
  if (!device?.deviceId) throw new Error("Not authenticated");

  let keys: Awaited<ReturnType<typeof encryptionApi.getWorkspaceKeysWithPop>>["keys"] = [];
  let currentKekVersion = 0;

  try {
    const keysResponse = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId, {
      signal,
    });
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

  if (activeKey && activeKey.sender_ecdh_public_key && activeKey.sender_signing_public_key) {
    const senderEcdhPk = base64UrlDecode(activeKey.sender_ecdh_public_key);
    const senderSigningPk = base64UrlDecode(activeKey.sender_signing_public_key);

    const tofuResult = await worker.tofuVerify({
      userId,
      deviceId: activeKey.sender_device_id,
      signingPublicKey: senderSigningPk,
      ecdhPublicKey: senderEcdhPk,
    });
    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      throw new Error("Key verification failed for KEK sender device.");
    }
    if (tofuResult.status === "first_seen") {
      await worker.tofuTrustDevice({
        userId,
        deviceId: activeKey.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
    } else if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({ userId, deviceId: activeKey.sender_device_id });
    }

    await worker.decryptKekFromDeviceEnvelope({
      workspaceId,
      userId,
      senderDeviceId: activeKey.sender_device_id,
      targetDeviceId: deviceId,
      senderEcdhPublic: senderEcdhPk,
      encryptedKek: base64UrlDecode(activeKey.encrypted_kek),
      nonce: base64UrlDecode(activeKey.nonce),
      keyVersion: currentKekVersion,
    });
    await worker.setActiveKekVersion(workspaceId, currentKekVersion);

    (async () => {
      try {
        await encryptionApi.getKekBackupWithPop(workspaceId);
      } catch {
        try {
          const backup = await worker.wrapKekWithUmk({
            workspaceId,
            userId,
            keyVersion: currentKekVersion,
          });
          await encryptionApi.createKekBackupWithPop(workspaceId, {
            key_version: currentKekVersion,
            encrypted_kek: base64UrlEncode(backup.encrypted),
            nonce: base64UrlEncode(backup.nonce),
          });
        } catch {
          /* fire-and-forget */
        }
      }
    })();
  } else {
    const envelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
    if (
      envelope &&
      envelope.sender_ecdh_public_key &&
      envelope.sender_signing_public_key &&
      envelope.key_version === currentKekVersion
    ) {
      const meSenderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
      const meSenderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);

      const meTofuResult = await worker.tofuVerify({
        userId: envelope.sender_user_id,
        deviceId: envelope.sender_device_id,
        signingPublicKey: meSenderSigningPk,
        ecdhPublicKey: meSenderEcdhPk,
      });
      if (
        meTofuResult.status === "identity_key_changed" ||
        meTofuResult.status === "ecdh_key_mismatch"
      ) {
        throw new Error("Key verification failed for member envelope sender.");
      }
      if (meTofuResult.status === "first_seen") {
        await worker.tofuTrustDevice({
          userId: envelope.sender_user_id,
          deviceId: envelope.sender_device_id,
          signingPublicKey: meSenderSigningPk,
          ecdhPublicKey: meSenderEcdhPk,
        });
      } else if (meTofuResult.status === "known_trusted") {
        await worker.tofuUpdateLastSeen({
          userId: envelope.sender_user_id,
          deviceId: envelope.sender_device_id,
        });
      }

      await worker.decryptKekFromMemberEnvelope({
        workspaceId,
        targetUserId: userId,
        senderDeviceId: envelope.sender_device_id,
        senderIdentityEcdhPublic: meSenderEcdhPk,
        encryptedKek: base64UrlDecode(envelope.encrypted_kek),
        nonce: base64UrlDecode(envelope.nonce),
        keyVersion: envelope.key_version,
      });
      await worker.setActiveKekVersion(workspaceId, currentKekVersion);

      const deviceEcdhPublic = device.deviceEcdhPublic;
      if (deviceEcdhPublic) {
        const deviceEnvelope = await worker.encryptKekForDevice({
          workspaceId,
          userId,
          senderDeviceId: deviceId,
          targetDeviceId: deviceId,
          targetDeviceEcdhPublic: deviceEcdhPublic,
          keyVersion: currentKekVersion,
        });
        try {
          await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
            device_id: deviceId,
            sender_device_id: deviceId,
            key_version: currentKekVersion,
            encrypted_kek: base64UrlEncode(deviceEnvelope.encrypted),
            nonce: base64UrlEncode(deviceEnvelope.nonce),
          });
        } catch (e) {
          if (!(e instanceof ApiError && e.status === 409)) throw e;
        }
      }

      const umkBackup = await worker.wrapKekWithUmk({
        workspaceId,
        userId,
        keyVersion: currentKekVersion,
      });
      try {
        await encryptionApi.createKekBackupWithPop(workspaceId, {
          key_version: currentKekVersion,
          encrypted_kek: base64UrlEncode(umkBackup.encrypted),
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

      await worker.unwrapKekFromBackup({
        workspaceId,
        userId,
        encryptedKek: base64UrlDecode(backupData.encrypted_kek),
        nonce: base64UrlDecode(backupData.nonce),
        keyVersion: backupData.key_version,
      });
      await worker.setActiveKekVersion(workspaceId, currentKekVersion);

      const deviceEcdhPublic = device.deviceEcdhPublic;
      if (deviceEcdhPublic) {
        const deviceEnvelope = await worker.encryptKekForDevice({
          workspaceId,
          userId,
          senderDeviceId: deviceId,
          targetDeviceId: deviceId,
          targetDeviceEcdhPublic: deviceEcdhPublic,
          keyVersion: currentKekVersion,
        });
        try {
          await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
            device_id: deviceId,
            sender_device_id: deviceId,
            key_version: currentKekVersion,
            encrypted_kek: base64UrlEncode(deviceEnvelope.encrypted),
            nonce: base64UrlEncode(deviceEnvelope.nonce),
          });
        } catch (e) {
          if (!(e instanceof ApiError && e.status === 409)) throw e;
        }
      }
    }
  }

  await worker.setActiveKekVersion(workspaceId, currentKekVersion);
  return { kekVersion: currentKekVersion };
}

/**
 * Resolve a specific KEK version for a workspace.
 * Used when unwrapping old DEKs that were wrapped with a previous KEK version.
 * Priority: worker cache → device envelope → UMK backup
 */
export async function resolveKekByVersion(
  workspaceId: string,
  keyVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  const worker = getCryptoWorker();
  const auth = authState();
  const device = deviceState();
  if (!auth || !device?.deviceId) throw new Error("Not authenticated");

  // 1. Check cache
  const cached = await worker.resolveKek(workspaceId, keyVersion);
  if (cached.found) return;

  const userId = auth.user.id;
  const deviceId = device.deviceId;

  // 2. Try device envelope (includes TOFU verification)
  const resolved = await tryDecryptKekViaDeviceEnvelope(
    worker,
    workspaceId,
    userId,
    deviceId,
    keyVersion,
    signal,
  );
  if (resolved) return;

  // 3. Try member envelope (TOFU verification included; only if version matches)
  let memberEnvelopeAttempted = false;
  try {
    const envelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
    if (
      envelope?.sender_ecdh_public_key &&
      envelope.sender_signing_public_key &&
      envelope.key_version === keyVersion
    ) {
      memberEnvelopeAttempted = true;
      const senderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
      const senderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);

      const tofuResult = await worker.tofuVerify({
        userId: envelope.sender_user_id,
        deviceId: envelope.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
      if (
        tofuResult.status === "identity_key_changed" ||
        tofuResult.status === "ecdh_key_mismatch"
      ) {
        throw new Error("Key verification failed for member envelope sender.");
      }
      if (tofuResult.status === "first_seen") {
        await worker.tofuTrustDevice({
          userId: envelope.sender_user_id,
          deviceId: envelope.sender_device_id,
          signingPublicKey: senderSigningPk,
          ecdhPublicKey: senderEcdhPk,
        });
      } else if (tofuResult.status === "known_trusted") {
        await worker.tofuUpdateLastSeen({
          userId: envelope.sender_user_id,
          deviceId: envelope.sender_device_id,
        });
      }

      await worker.decryptKekFromMemberEnvelope({
        workspaceId,
        targetUserId: userId,
        senderDeviceId: envelope.sender_device_id,
        senderIdentityEcdhPublic: senderEcdhPk,
        encryptedKek: base64UrlDecode(envelope.encrypted_kek),
        nonce: base64UrlDecode(envelope.nonce),
        keyVersion: envelope.key_version,
      });
      return;
    }
  } catch (err) {
    if (memberEnvelopeAttempted) throw err; // TOFU hard-fail must not be suppressed
  }

  // 4. UMK backup fallback (version-specific; no TOFU needed — user's own backup)
  const backupData = await encryptionApi.getKekBackupWithPop(workspaceId, keyVersion);
  await worker.unwrapKekFromBackup({
    workspaceId,
    userId,
    encryptedKek: base64UrlDecode(backupData.encrypted_kek),
    nonce: base64UrlDecode(backupData.nonce),
    keyVersion: backupData.key_version,
  });
}

async function tryDecryptKekViaDeviceEnvelope(
  worker: ReturnType<typeof getCryptoWorker>,
  workspaceId: string,
  userId: string,
  deviceId: string,
  keyVersion: number,
  signal?: AbortSignal,
): Promise<boolean> {
  let envelopeFound = false;
  try {
    const keysResponse = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId, {
      signal,
    });
    const matchingKey = keysResponse.keys.find((k) => k.key_version === keyVersion);

    if (!matchingKey?.sender_ecdh_public_key || !matchingKey.sender_signing_public_key) {
      return false;
    }

    envelopeFound = true;
    const senderEcdhPk = base64UrlDecode(matchingKey.sender_ecdh_public_key);
    const senderSigningPk = base64UrlDecode(matchingKey.sender_signing_public_key);

    // TOFU verification before any key use
    const tofuResult = await worker.tofuVerify({
      userId,
      deviceId: matchingKey.sender_device_id,
      signingPublicKey: senderSigningPk,
      ecdhPublicKey: senderEcdhPk,
    });
    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      throw new Error("Key verification failed for KEK sender device.");
    }
    if (tofuResult.status === "first_seen") {
      await worker.tofuTrustDevice({
        userId,
        deviceId: matchingKey.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
    } else if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({ userId, deviceId: matchingKey.sender_device_id });
    }

    await worker.decryptKekFromDeviceEnvelope({
      workspaceId,
      userId,
      senderDeviceId: matchingKey.sender_device_id,
      targetDeviceId: deviceId,
      senderEcdhPublic: senderEcdhPk,
      encryptedKek: base64UrlDecode(matchingKey.encrypted_kek),
      nonce: base64UrlDecode(matchingKey.nonce),
      keyVersion,
    });
    return true;
  } catch (err) {
    if (envelopeFound) throw err;
    return false;
  }
}
