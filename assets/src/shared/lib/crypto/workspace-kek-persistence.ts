import { encryptionApi } from "@/shared/api/encryption";
import { ApiError } from "@/shared/api/core";
import { base64UrlEncode } from "./encoding";
import { getCryptoWorker } from "./worker/client";
interface ConflictHandlingOptions {
  ignoreConflict?: boolean;
}
interface PersistWorkspaceKekForDeviceParams extends ConflictHandlingOptions {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
  targetDeviceId: string;
  targetDeviceEcdhPublic: Uint8Array;
  keyVersion: number;
  isActive?: boolean;
  popDeviceId?: string;
}
interface PersistWorkspaceKekBackupParams extends ConflictHandlingOptions {
  workspaceId: string;
  userId: string;
  keyVersion: number;
  popDeviceId?: string;
}
interface PersistWorkspaceKekLocallyParams extends ConflictHandlingOptions {
  workspaceId: string;
  userId: string;
  deviceId: string;
  deviceEcdhPublic: Uint8Array | null;
  keyVersion: number;
  isActive?: boolean;
}
function shouldIgnoreConflict(error: unknown, ignoreConflict: boolean): boolean {
  return ignoreConflict && error instanceof ApiError && error.status === 409;
}
export async function persistWorkspaceKekForDevice({
  workspaceId,
  userId,
  senderDeviceId,
  targetDeviceId,
  targetDeviceEcdhPublic,
  keyVersion,
  isActive,
  popDeviceId,
  ignoreConflict = false,
}: PersistWorkspaceKekForDeviceParams): Promise<void> {
  const worker = getCryptoWorker();
  const envelope = await worker.encryptKekForDevice({
    workspaceId,
    userId,
    senderDeviceId,
    targetDeviceId,
    targetDeviceEcdhPublic,
    keyVersion,
  });
  try {
    await encryptionApi.createWorkspaceKeyWithPop(
      workspaceId,
      {
        device_id: targetDeviceId,
        sender_device_id: senderDeviceId,
        encrypted_kek: base64UrlEncode(envelope.encrypted),
        nonce: base64UrlEncode(envelope.nonce),
        key_version: keyVersion,
        is_active: isActive,
      },
      {
        popDeviceId,
      },
    );
  } catch (error) {
    if (!shouldIgnoreConflict(error, ignoreConflict)) {
      throw error;
    }
  }
}
export async function persistWorkspaceKekBackup({
  workspaceId,
  userId,
  keyVersion,
  popDeviceId,
  ignoreConflict = false,
}: PersistWorkspaceKekBackupParams): Promise<void> {
  const worker = getCryptoWorker();
  const backup = await worker.wrapKekWithUmk({
    workspaceId,
    userId,
    keyVersion,
  });
  try {
    await encryptionApi.createKekBackupWithPop(
      workspaceId,
      {
        key_version: keyVersion,
        encrypted_kek: base64UrlEncode(backup.encrypted),
        nonce: base64UrlEncode(backup.nonce),
      },
      {
        popDeviceId,
      },
    );
  } catch (error) {
    if (!shouldIgnoreConflict(error, ignoreConflict)) {
      throw error;
    }
  }
}
export async function persistWorkspaceKekLocally({
  workspaceId,
  userId,
  deviceId,
  deviceEcdhPublic,
  keyVersion,
  isActive,
  ignoreConflict = false,
}: PersistWorkspaceKekLocallyParams): Promise<void> {
  if (!deviceEcdhPublic) {
    throw new Error("Device ECDH public key not available");
  }
  await persistWorkspaceKekForDevice({
    workspaceId,
    userId,
    senderDeviceId: deviceId,
    targetDeviceId: deviceId,
    targetDeviceEcdhPublic: deviceEcdhPublic,
    keyVersion,
    isActive,
    popDeviceId: deviceId,
    ignoreConflict,
  });
  await persistWorkspaceKekBackup({
    workspaceId,
    userId,
    keyVersion,
    popDeviceId: deviceId,
    ignoreConflict,
  });
}
