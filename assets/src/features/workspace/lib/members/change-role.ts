import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { workspacesApi, type components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildWorkspaceMemberRoleChangeKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/membership-events";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

export async function changeWorkspaceMemberRoleWithKeyDirectory(input: {
  workspaceId: string;
  targetUserId: string;
  previousRoleId: string;
  previousBaseRole: string;
  roleId: string;
}): Promise<components["schemas"]["OkResponse"]> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  const [directory, roles] = await Promise.all([
    fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      rrpDeviceId: currentDevice.deviceId,
    }),
    workspacesApi.listRoles(input.workspaceId),
  ]);
  const targetRole = roles.roles.find((role) => role.id === input.roleId);
  if (!targetRole) throw new Error("Role not found");

  const keyDirectoryAppend = await buildWorkspaceMemberRoleChangeKeyDirectoryAppend({
    workspaceId: input.workspaceId,
    actorUserId: auth.user.id,
    actorDeviceId: currentDevice.deviceId,
    targetUserId: input.targetUserId,
    previousRoleId: input.previousRoleId,
    previousBaseRole: input.previousBaseRole,
    roleId: input.roleId,
    baseRole: targetRole.base_role,
    checkpointEnvelope: directory.checkpoint,
  });
  const response = await workspacesApi.changeMemberRole(input.workspaceId, input.targetUserId, {
    role_id: input.roleId,
    workspace_key_directory_events: keyDirectoryAppend.events,
    workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
  });
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    checkpointEnvelope: keyDirectoryAppend.checkpoint,
    checkpointAncestry: [directory.checkpoint],
    eventAncestry: keyDirectoryAppend.events,
  });
  return response as components["schemas"]["OkResponse"];
}
