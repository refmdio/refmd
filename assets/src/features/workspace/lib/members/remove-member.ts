import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { workspacesApi, type components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildWorkspaceMemberRemovalKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/membership-events";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

type RemoveMemberResponse = components["schemas"]["RemoveMemberResponse"];

export async function removeWorkspaceMemberWithKeyDirectory(
  workspaceId: string,
  targetUserId: string,
): Promise<RemoveMemberResponse> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  const [directory, targetDevices] = await Promise.all([
    fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      popDeviceId: currentDevice.deviceId,
    }),
    workspacesApi.listMemberDevices(workspaceId, targetUserId, false),
  ]);
  const keyDirectoryAppend = await buildWorkspaceMemberRemovalKeyDirectoryAppend({
    workspaceId,
    actorUserId: auth.user.id,
    actorDeviceId: currentDevice.deviceId,
    removedUserId: targetUserId,
    checkpointEnvelope: directory.checkpoint,
    removedDeviceKeys: targetDevices.devices.map((device) => ({
      signingKeyId: device.signing_key_id,
      encryptionKeyId: device.encryption_key_id,
    })),
  });
  const response = await workspacesApi.removeMember(workspaceId, targetUserId, {
    workspace_key_directory_events: keyDirectoryAppend.events,
    workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
  });
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope: keyDirectoryAppend.checkpoint,
    checkpointAncestry: [directory.checkpoint],
    eventAncestry: keyDirectoryAppend.events,
  });
  return response as RemoveMemberResponse;
}
