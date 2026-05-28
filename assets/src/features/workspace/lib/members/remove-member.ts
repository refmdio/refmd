import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, workspacesApi, type components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildWorkspaceMemberRemovalKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/membership-events";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

type RemoveMemberResponse = components["schemas"]["RemoveMemberResponse"];
const KEY_DIRECTORY_APPEND_ATTEMPTS = 2;

export async function removeWorkspaceMemberWithKeyDirectory(
  workspaceId: string,
  targetUserId: string,
): Promise<RemoveMemberResponse> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  let directory: Awaited<ReturnType<typeof fetchVerifiedKeyDirectory>> | null = null;
  let keyDirectoryAppend: Awaited<
    ReturnType<typeof buildWorkspaceMemberRemovalKeyDirectoryAppend>
  > | null = null;
  let response: RemoveMemberResponse | null = null;

  for (let attempt = 0; attempt < KEY_DIRECTORY_APPEND_ATTEMPTS; attempt += 1) {
    const [nextDirectory, targetDevices] = await Promise.all([
      fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        popDeviceId: currentDevice.deviceId,
      }),
      workspacesApi.listMemberDevices(workspaceId, targetUserId, false),
    ]);
    directory = nextDirectory;
    keyDirectoryAppend = await buildWorkspaceMemberRemovalKeyDirectoryAppend({
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
    try {
      response = (await workspacesApi.removeMember(workspaceId, targetUserId, {
        workspace_key_directory_events: keyDirectoryAppend.events,
        workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
      })) as RemoveMemberResponse;
      break;
    } catch (error) {
      if (!isInvalidKeyDirectoryError(error) || attempt === KEY_DIRECTORY_APPEND_ATTEMPTS - 1) {
        throw error;
      }
    }
  }

  if (!directory || !keyDirectoryAppend || !response) {
    throw new Error("workspace_member_removal_response_missing");
  }

  if (targetUserId === auth.user.id) {
    void advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: keyDirectoryAppend.checkpoint,
      checkpointAncestry: [directory.checkpoint],
      eventAncestry: keyDirectoryAppend.events,
    }).catch(() => undefined);
    return response as RemoveMemberResponse;
  }

  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope: keyDirectoryAppend.checkpoint,
    checkpointAncestry: [directory.checkpoint],
    eventAncestry: keyDirectoryAppend.events,
  });
  return response as RemoveMemberResponse;
}

function isInvalidKeyDirectoryError(error: unknown): boolean {
  return error instanceof ApiError && error.code === "invalid_key_directory";
}
