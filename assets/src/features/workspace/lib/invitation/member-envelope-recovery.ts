import type { AuthState, DeviceState } from "@/entities/session";
import { encryptionApi } from "@/shared/api";
import { openAdmittedWorkspaceMemberKekEnvelope } from "@/shared/lib/crypto/kek-resolver";
import { persistWorkspaceKekForDevice } from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export async function recoverWorkspaceInvitationMemberEnvelope(
  workspaceId: string,
  auth: AuthState,
  device: Pick<DeviceState, "deviceId">,
): Promise<void> {
  const envelope = await encryptionApi.getMemberEnvelopeWithRrp(workspaceId);
  if (!envelope) throw new Error("member_envelope_missing");

  await openAdmittedWorkspaceMemberKekEnvelope(
    workspaceId,
    envelope as unknown as Record<string, unknown>,
  );
  const worker = getCryptoWorker();
  const publicKeys = await worker.getPublicKeys();
  if (!publicKeys.deviceHybridEncryptionPublicKeyMaterial) {
    throw new Error("Device hybrid encryption key material is not available.");
  }
  await persistWorkspaceKekForDevice({
    workspaceId,
    userId: auth.user.id,
    senderDeviceId: device.deviceId,
    targetDeviceId: device.deviceId,
    targetDeviceHybridEncryptionPublicKeyMaterial:
      publicKeys.deviceHybridEncryptionPublicKeyMaterial,
    keyVersion: envelope.key_version,
    ignoreConflict: true,
  });
}
