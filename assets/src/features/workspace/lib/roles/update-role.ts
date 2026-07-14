import { ALL_PERMISSIONS, checkEffectivePermission } from "@/entities/workspace";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError, workspacesApi, type components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildWorkspaceMemberRoleChangesKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/membership-events";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

type Role = components["schemas"]["RoleResponse"];
type PermissionOverride = components["schemas"]["PermissionOverride"];
const KEY_DIRECTORY_APPEND_ATTEMPTS = 2;

export async function updateWorkspaceRoleWithKeyDirectory(input: {
  workspaceId: string;
  role: Role;
  name?: string;
  permissions: PermissionOverride[];
}): Promise<components["schemas"]["UpdateRoleResponse"]> {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("Identity keys or device not available");
  }

  const [rolesResponse, membersResponse] = await Promise.all([
    workspacesApi.listRoles(input.workspaceId),
    workspacesApi.listMembers(input.workspaceId),
  ]);
  const currentRole = rolesResponse.roles.find((role) => role.id === input.role.id);
  if (!currentRole) throw new Error("Role not found");

  const proposedRole: Role = { ...currentRole, permissions: input.permissions };
  const previousPermissions = effectivePermissions(rolesResponse.roles, currentRole.id);
  const proposedRoles = rolesResponse.roles.map((role) =>
    role.id === proposedRole.id ? proposedRole : role,
  );
  const nextPermissions = effectivePermissions(proposedRoles, proposedRole.id);
  const affectedMembers = membersResponse.members
    .filter((member) => member.role_id === currentRole.id)
    .sort((left, right) => left.user_id.localeCompare(right.user_id));
  const effectivePermissionsChanged = !samePermissions(previousPermissions, nextPermissions);

  if (!effectivePermissionsChanged || affectedMembers.length === 0) {
    return workspacesApi.updateRole(input.workspaceId, input.role.id, {
      name: input.name,
      permissions: input.permissions,
    }) as Promise<components["schemas"]["UpdateRoleResponse"]>;
  }

  let directory: Awaited<ReturnType<typeof fetchVerifiedKeyDirectory>> | null = null;
  let append: Awaited<ReturnType<typeof buildWorkspaceMemberRoleChangesKeyDirectoryAppend>> | null =
    null;
  let response: components["schemas"]["UpdateRoleResponse"] | null = null;

  for (let attempt = 0; attempt < KEY_DIRECTORY_APPEND_ATTEMPTS; attempt += 1) {
    directory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      rrpDeviceId: currentDevice.deviceId,
    });
    append = await buildWorkspaceMemberRoleChangesKeyDirectoryAppend({
      workspaceId: input.workspaceId,
      actorUserId: auth.user.id,
      actorDeviceId: currentDevice.deviceId,
      changes: affectedMembers.map((member) => ({
        targetUserId: member.user_id,
        previousRoleId: currentRole.id,
        previousBaseRole: currentRole.base_role,
        previousEffectivePermissions: previousPermissions,
        roleId: currentRole.id,
        baseRole: currentRole.base_role,
        effectivePermissions: nextPermissions,
        permissionVersion: member.permission_version + 1,
      })),
      checkpointEnvelope: directory.checkpoint,
    });
    try {
      response = await workspacesApi.updateRole(input.workspaceId, input.role.id, {
        name: input.name,
        permissions: input.permissions,
        workspace_key_directory_events: append.events,
        workspace_key_directory_checkpoint: append.checkpoint,
      });
      break;
    } catch (error) {
      if (!isInvalidKeyDirectoryError(error) || attempt === KEY_DIRECTORY_APPEND_ATTEMPTS - 1) {
        throw error;
      }
    }
  }

  if (!directory || !append || !response) {
    throw new Error("workspace_role_update_response_missing");
  }
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    checkpointEnvelope: append.checkpoint,
    checkpointAncestry: [directory.checkpoint],
    eventAncestry: append.events,
  });
  return response;
}

function effectivePermissions(roles: Role[], roleId: string): string[] {
  return ALL_PERMISSIONS.filter((permission) =>
    checkEffectivePermission(roles, roleId, permission),
  ).sort();
}

function samePermissions(left: string[], right: string[]): boolean {
  return (
    left.length === right.length && left.every((permission, index) => permission === right[index])
  );
}

function isInvalidKeyDirectoryError(error: unknown): boolean {
  return error instanceof ApiError && error.code === "invalid_key_directory";
}
