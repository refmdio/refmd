import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, workspacesApi, type components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildWorkspaceMemberRoleChangesKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/membership-events";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { ALL_PERMISSIONS, checkEffectivePermission } from "@/entities/workspace";

const KEY_DIRECTORY_APPEND_ATTEMPTS = 2;

export async function changeWorkspaceMemberRoleWithKeyDirectory(input: {
  workspaceId: string;
  targetUserId: string;
  previousRoleId: string;
  previousBaseRole: string;
  permissionVersion: number;
  roleId: string;
}): Promise<components["schemas"]["ChangeMemberRoleResponse"]> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  const roles = await workspacesApi.listRoles(input.workspaceId);
  const targetRole = roles.roles.find((role) => role.id === input.roleId);
  const previousRole = roles.roles.find((role) => role.id === input.previousRoleId);
  if (!targetRole) throw new Error("Role not found");
  if (!previousRole) throw new Error("Previous role not found");

  const effectivePermissions = (roleId: string) =>
    ALL_PERMISSIONS.filter((permission) =>
      checkEffectivePermission(roles.roles, roleId, permission),
    ).sort();

  let directory: Awaited<ReturnType<typeof fetchVerifiedKeyDirectory>> | null = null;
  let keyDirectoryAppend: Awaited<
    ReturnType<typeof buildWorkspaceMemberRoleChangesKeyDirectoryAppend>
  > | null = null;
  let response: components["schemas"]["ChangeMemberRoleResponse"] | null = null;

  for (let attempt = 0; attempt < KEY_DIRECTORY_APPEND_ATTEMPTS; attempt += 1) {
    directory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      rrpDeviceId: currentDevice.deviceId,
    });
    keyDirectoryAppend = await buildWorkspaceMemberRoleChangesKeyDirectoryAppend({
      workspaceId: input.workspaceId,
      actorUserId: auth.user.id,
      actorDeviceId: currentDevice.deviceId,
      changes: [
        {
          targetUserId: input.targetUserId,
          previousRoleId: input.previousRoleId,
          previousBaseRole: input.previousBaseRole,
          previousEffectivePermissions: effectivePermissions(input.previousRoleId),
          roleId: input.roleId,
          baseRole: targetRole.base_role,
          effectivePermissions: effectivePermissions(input.roleId),
          permissionVersion: input.permissionVersion + 1,
        },
      ],
      checkpointEnvelope: directory.checkpoint,
    });
    try {
      response = await workspacesApi.changeMemberRole(input.workspaceId, input.targetUserId, {
        role_id: input.roleId,
        workspace_key_directory_events: keyDirectoryAppend.events,
        workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
      });
      break;
    } catch (error) {
      if (!isInvalidKeyDirectoryError(error) || attempt === KEY_DIRECTORY_APPEND_ATTEMPTS - 1) {
        throw error;
      }
    }
  }

  if (!directory || !keyDirectoryAppend || !response) {
    throw new Error("workspace_member_role_change_response_missing");
  }
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    checkpointEnvelope: keyDirectoryAppend.checkpoint,
    checkpointAncestry: [directory.checkpoint],
    eventAncestry: keyDirectoryAppend.events,
  });
  return response;
}

function isInvalidKeyDirectoryError(error: unknown): boolean {
  return error instanceof ApiError && error.code === "invalid_key_directory";
}
