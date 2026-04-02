import { encryptionApi, ApiError } from "@/shared/api";
import { base64UrlDecode } from "./encoding";
import {
  persistWorkspaceKekBackup,
  persistWorkspaceKekForDevice,
} from "./workspace-kek-persistence";
import { getCryptoWorker } from "./worker/client";
import { KekResolutionError } from "./kek-resolver-error";
import { verifyAndHandleTofu } from "./tofu-status";
const pendingActiveKekResolutions = new Map<
  string,
  Promise<{
    kekVersion: number;
  }>
>();
interface KekResolverAuthState {
  user: {
    id: string;
  };
}
interface KekResolverDeviceState {
  deviceId: string;
  deviceEcdhPublic: Uint8Array | null;
}
export interface KekResolverSession {
  auth: KekResolverAuthState | null;
  device: KekResolverDeviceState | null;
}
function requireKekResolverSession(session: KekResolverSession): {
  auth: KekResolverAuthState;
  device: KekResolverDeviceState;
} {
  if (!session.auth || !session.device?.deviceId) {
    throw new Error("Not authenticated");
  }
  return {
    auth: session.auth,
    device: session.device,
  };
}
export async function resolveActiveKek(
  workspaceId: string,
  session: KekResolverSession,
  signal?: AbortSignal,
): Promise<{
  kekVersion: number;
}> {
  const worker = getCryptoWorker();
  const { auth, device } = requireKekResolverSession(session);
  const cached = await worker.resolveKek(workspaceId);
  if (cached.found && cached.keyVersion !== undefined) {
    await worker.setActiveKekVersion(workspaceId, cached.keyVersion);
    return { kekVersion: cached.keyVersion };
  }
  if (signal) {
    return doResolveActiveKek(workspaceId, auth.user.id, device, worker, signal);
  }
  const pending = pendingActiveKekResolutions.get(workspaceId);
  if (pending) return pending;
  const resolution = doResolveActiveKek(workspaceId, auth.user.id, device, worker, signal);
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
  device: KekResolverDeviceState,
  worker: ReturnType<typeof getCryptoWorker>,
  signal?: AbortSignal,
): Promise<{
  kekVersion: number;
}> {
  const deviceId = device.deviceId;
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
    throw new KekResolutionError(workspaceId, "Encryption not set up for this workspace");
  }
  const activeKey = keys.find((k) => k.key_version === currentKekVersion);
  if (activeKey && activeKey.sender_ecdh_public_key && activeKey.sender_signing_public_key) {
    const senderEcdhPk = base64UrlDecode(activeKey.sender_ecdh_public_key);
    const senderSigningPk = base64UrlDecode(activeKey.sender_signing_public_key);
    try {
      await verifyAndHandleTofu({
        userId,
        deviceId: activeKey.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
    } catch {
      throw new KekResolutionError(workspaceId, "Key verification failed for KEK sender device.");
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
          await persistWorkspaceKekBackup({
            workspaceId,
            userId,
            keyVersion: currentKekVersion,
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
      try {
        await verifyAndHandleTofu({
          userId: envelope.sender_user_id,
          deviceId: envelope.sender_device_id,
          signingPublicKey: meSenderSigningPk,
          ecdhPublicKey: meSenderEcdhPk,
        });
      } catch {
        throw new KekResolutionError(
          workspaceId,
          "Key verification failed for member envelope sender.",
        );
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
        await persistWorkspaceKekForDevice({
          workspaceId,
          userId,
          senderDeviceId: deviceId,
          targetDeviceId: deviceId,
          targetDeviceEcdhPublic: deviceEcdhPublic,
          keyVersion: currentKekVersion,
          ignoreConflict: true,
        });
      }
      await persistWorkspaceKekBackup({
        workspaceId,
        userId,
        keyVersion: currentKekVersion,
        ignoreConflict: true,
      });
    } else {
      let backupData: {
        encrypted_kek: string;
        nonce: string;
        key_version: number;
      };
      try {
        backupData = await encryptionApi.getKekBackupWithPop(workspaceId);
      } catch {
        throw new KekResolutionError(
          workspaceId,
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
        await persistWorkspaceKekForDevice({
          workspaceId,
          userId,
          senderDeviceId: deviceId,
          targetDeviceId: deviceId,
          targetDeviceEcdhPublic: deviceEcdhPublic,
          keyVersion: currentKekVersion,
          ignoreConflict: true,
        });
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
  session: KekResolverSession,
  signal?: AbortSignal,
): Promise<void> {
  const worker = getCryptoWorker();
  const { auth, device } = requireKekResolverSession(session);
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
      try {
        await verifyAndHandleTofu({
          userId: envelope.sender_user_id,
          deviceId: envelope.sender_device_id,
          signingPublicKey: senderSigningPk,
          ecdhPublicKey: senderEcdhPk,
        });
      } catch {
        throw new KekResolutionError(
          workspaceId,
          "Key verification failed for member envelope sender.",
        );
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
    try {
      await verifyAndHandleTofu({
        userId,
        deviceId: matchingKey.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
    } catch {
      throw new KekResolutionError(workspaceId, "Key verification failed for KEK sender device.");
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
