import { encryptionApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import { openAdmittedWorkspaceMemberKekEnvelope } from "@/shared/lib/crypto/kek-resolver";
import { persistWorkspaceKekLocally } from "@/shared/lib/crypto/workspace-kek-persistence";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface KekRestoreResults {
  restored: string[];
  failed: string[];
}

export async function restoreWorkspaceKeks(
  userId: string,
  deviceId: string,
  _identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null,
  _identityEcdhPublic: Uint8Array | null,
): Promise<KekRestoreResults> {
  const result: KekRestoreResults = { restored: [], failed: [] };
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds({
    rrpDeviceId: deviceId,
  });

  for (const workspaceId of workspaceIds) {
    try {
      const status = await restoreKekForWorkspace(workspaceId, userId, deviceId);
      if (status === "restored") {
        result.restored.push(workspaceId);
      } else {
        result.failed.push(`${workspaceId}:needs_distribution`);
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      result.failed.push(`${workspaceId}:${reason}`);
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
    const existing = await encryptionApi.getWorkspaceKeysWithRrp(workspaceId, deviceId, {
      rrpDeviceId: deviceId,
    });
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

  if (currentKekVersion > 0) {
    return restoreKekFromMemberEnvelope(workspaceId, userId, deviceId);
  }

  await worker.generateKek(workspaceId);

  const publicKeys = await worker.getPublicKeys();

  try {
    await persistWorkspaceKekLocally({
      workspaceId,
      userId,
      deviceId,
      deviceHybridEncryptionPublicKeyMaterial: publicKeys.deviceHybridEncryptionPublicKeyMaterial,
      keyVersion: 1,
      isActive: true,
    });
    return "restored";
  } catch {
    return "needs_distribution";
  }
}

async function restoreKekFromMemberEnvelope(
  workspaceId: string,
  userId: string,
  deviceId: string,
): Promise<"restored" | "needs_distribution"> {
  const envelope = await encryptionApi.getMemberEnvelopeWithRrp(workspaceId, {
    rrpDeviceId: deviceId,
  });
  if (!envelope) return "needs_distribution";

  const worker = getCryptoWorker();
  await openAdmittedWorkspaceMemberKekEnvelope(
    workspaceId,
    envelope as unknown as Record<string, unknown>,
  );

  const publicKeys = await worker.getPublicKeys();
  if (
    !publicKeys.deviceHybridSigningPublicKeyMaterial ||
    !publicKeys.deviceHybridEncryptionPublicKeyMaterial
  ) {
    throw new Error("recovery_device_key_material_missing");
  }

  await persistWorkspaceKekLocally({
    workspaceId,
    userId,
    deviceId,
    deviceHybridEncryptionPublicKeyMaterial: publicKeys.deviceHybridEncryptionPublicKeyMaterial,
    keyVersion: envelope.key_version,
    isActive: true,
    ignoreConflict: true,
  });

  return "restored";
}
