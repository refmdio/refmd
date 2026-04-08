import { encryptionApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import {
  persistWorkspaceKekForDevice,
  persistWorkspaceKekLocally,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface KekRestoreResults {
  needsDistribution: string[];
  backupDecryptFailed: boolean;
}

class BackupDecryptError extends Error {
  constructor(workspaceId: string) {
    super(`KEK backup decryption failed for workspace ${workspaceId}`);
    this.name = "BackupDecryptError";
  }
}

export async function restoreWorkspaceKeks(
  userId: string,
  deviceId: string,
): Promise<KekRestoreResults> {
  const result: KekRestoreResults = { needsDistribution: [], backupDecryptFailed: false };
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds();

  for (const workspaceId of workspaceIds) {
    try {
      const status = await restoreKekForWorkspace(workspaceId, userId, deviceId);
      if (status === "needs_distribution") {
        result.needsDistribution.push(workspaceId);
      }
    } catch (error) {
      if (error instanceof BackupDecryptError) {
        result.backupDecryptFailed = true;
      }
      // Other errors (network, etc.) are non-fatal per-workspace.
    }
  }

  return result;
}

async function restoreKekForWorkspace(
  workspaceId: string,
  userId: string,
  deviceId: string,
): Promise<"restored" | "needs_distribution"> {
  const worker = getCryptoWorker();

  let currentKekVersion = 0;
  try {
    const existing = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId);
    if (existing.keys.some((key) => key.is_active)) return "restored";
    currentKekVersion = existing.current_kek_version;
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      currentKekVersion =
        (error.body.details as { current_kek_version?: number })?.current_kek_version ?? 0;
    } else {
      throw error;
    }
  }

  const memberEnvelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (
    memberEnvelope &&
    memberEnvelope.sender_ecdh_public_key &&
    memberEnvelope.sender_signing_public_key
  ) {
    const senderEcdhPublic = base64UrlDecode(memberEnvelope.sender_ecdh_public_key);
    const senderSigningPublic = base64UrlDecode(memberEnvelope.sender_signing_public_key);

    const tofuResult = await worker.tofuVerify({
      userId: memberEnvelope.sender_user_id,
      deviceId: memberEnvelope.sender_device_id,
      signingPublicKey: senderSigningPublic,
      ecdhPublicKey: senderEcdhPublic,
    });
    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      throw new Error("Key verification failed for member envelope sender. Aborting KEK recovery.");
    }
    if (tofuResult.status === "first_seen") {
      await worker.tofuTrustDevice({
        userId: memberEnvelope.sender_user_id,
        deviceId: memberEnvelope.sender_device_id,
        signingPublicKey: senderSigningPublic,
        ecdhPublicKey: senderEcdhPublic,
      });
    } else if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({
        userId: memberEnvelope.sender_user_id,
        deviceId: memberEnvelope.sender_device_id,
      });
    }

    await worker.decryptKekFromMemberEnvelope({
      encryptedKek: base64UrlDecode(memberEnvelope.encrypted_kek),
      nonce: base64UrlDecode(memberEnvelope.nonce),
      senderIdentityEcdhPublic: senderEcdhPublic,
      workspaceId,
      targetUserId: userId,
      keyVersion: memberEnvelope.key_version,
      senderDeviceId: memberEnvelope.sender_device_id,
    });

    const publicKeys = await worker.getPublicKeys();
    await persistWorkspaceKekLocally({
      workspaceId,
      userId,
      deviceId,
      deviceEcdhPublic: publicKeys.deviceEcdhPublic,
      keyVersion: memberEnvelope.key_version,
    });

    return "restored";
  }

  let backupData: { encrypted_kek: string; nonce: string; key_version: number } | null = null;
  try {
    backupData = await encryptionApi.getKekBackupWithPop(workspaceId);
  } catch {
    // No backup available.
  }

  if (backupData) {
    try {
      await worker.unwrapKekFromBackup({
        encryptedKek: base64UrlDecode(backupData.encrypted_kek),
        nonce: base64UrlDecode(backupData.nonce),
        workspaceId,
        userId,
        keyVersion: backupData.key_version,
      });
    } catch {
      throw new BackupDecryptError(workspaceId);
    }

    const publicKeys = await worker.getPublicKeys();
    await persistWorkspaceKekForDevice({
      workspaceId,
      userId,
      senderDeviceId: deviceId,
      targetDeviceId: deviceId,
      targetDeviceEcdhPublic: publicKeys.deviceEcdhPublic,
      keyVersion: backupData.key_version,
      ignoreConflict: true,
    });

    return "restored";
  }

  if (currentKekVersion > 0) return "needs_distribution";

  await worker.generateKek(workspaceId);

  const publicKeys = await worker.getPublicKeys();

  try {
    await persistWorkspaceKekLocally({
      workspaceId,
      userId,
      deviceId,
      deviceEcdhPublic: publicKeys.deviceEcdhPublic,
      keyVersion: 1,
      isActive: true,
    });
    return "restored";
  } catch {
    return "needs_distribution";
  }
}
