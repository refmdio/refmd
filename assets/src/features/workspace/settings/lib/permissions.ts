import type { Accessor } from "solid-js";
import { type components } from "@/shared/api";
import {
  ALL_PERMISSIONS,
  PRIVILEGE_LEVEL,
  checkEffectivePermission,
  type BaseRole,
} from "@/entities/workspace";

type WorkspaceRole = components["schemas"]["RoleResponse"];

type WorkspacePermissionMember = {
  role_id: string;
  base_role: string;
};

interface UseWorkspacePermissionsOptions {
  currentMember: Accessor<WorkspacePermissionMember | undefined>;
  roles: Accessor<WorkspaceRole[] | undefined>;
}

export function useWorkspacePermissions(options: UseWorkspacePermissionsOptions) {
  const currentMember = () => options.currentMember();
  const roles = () => options.roles();

  const hasPermission = (permission: string) => {
    const member = currentMember();
    const roleList = roles();
    if (!member || !roleList) return false;
    return checkEffectivePermission(roleList, member.role_id, permission);
  };

  const canUpdateWorkspace = () => hasPermission("workspace:update");
  const canManageFeatures = () => hasPermission("workspace:features");
  const canInvite = () => hasPermission("member:invite");
  const canInviteGuests = () => hasPermission("guest:invite");
  const canChangeRole = () => hasPermission("member:change_role");
  const canRemoveMember = () => hasPermission("member:remove");
  const canManageRoles = () => hasPermission("role:manage");

  const assignableRoles = () => {
    const member = currentMember();
    const roleList = roles();
    if (!member || !roleList) return [];

    const actorPower = PRIVILEGE_LEVEL[member.base_role as BaseRole] ?? 0;
    const actorPerms = new Set(
      ALL_PERMISSIONS.filter((permission) =>
        checkEffectivePermission(roleList, member.role_id, permission),
      ),
    );

    return roleList.filter((role: WorkspaceRole) => {
      if (PRIVILEGE_LEVEL[role.base_role as BaseRole] > actorPower) return false;

      return ALL_PERMISSIONS.every((permission) => {
        if (!checkEffectivePermission(roleList, role.id, permission)) return true;
        return actorPerms.has(permission);
      });
    });
  };

  const defaultRoleAssignable = () => {
    const roleList = roles();
    if (!roleList) return true;

    const defaultRole = roleList.find((role: WorkspaceRole) => role.is_default);
    if (!defaultRole) return true;

    return assignableRoles().some((role: WorkspaceRole) => role.id === defaultRole.id);
  };

  return {
    hasPermission,
    canUpdateWorkspace,
    canManageFeatures,
    canInvite,
    canInviteGuests,
    canChangeRole,
    canRemoveMember,
    canManageRoles,
    assignableRoles,
    defaultRoleAssignable,
  };
}
