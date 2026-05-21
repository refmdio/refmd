import { createSignal, type Accessor } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { authState, deviceState } from "@/entities/session";
import { type components, workspacesApi } from "@/shared/api";
import { isAtOrAbove, type BaseRole } from "@/entities/workspace";
import {
  buildRolePermissions,
  getPermissionOverrideState,
  togglePermissionOverride,
  type PermissionOverrideMap,
} from "../../lib/roles/permission-overrides";

type WorkspaceRole = components["schemas"]["RoleResponse"];
type RoleDeleteResponse = components["schemas"]["RoleDeleteResponse"];

interface UseWorkspaceRoleManagementOptions {
  workspaceId: Accessor<string | null | undefined>;
  setError: (value: string | null) => void;
  setInfo: (value: string | null) => void;
}

export function useWorkspaceRoleManagement(options: UseWorkspaceRoleManagementOptions) {
  const queryClient = useQueryClient();
  const workspaceId = () => options.workspaceId();

  const roles = createQuery(() => ({
    queryKey: ["workspace-roles", workspaceId()],
    queryFn: () => workspacesApi.listRoles(workspaceId()!),
    enabled: !!authState() && !!deviceState() && !!workspaceId(),
  }));

  const invalidateRoles = () => {
    const id = workspaceId();
    if (!id) return;

    queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-members", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });
  };

  const [createDialogOpen, setCreateDialogOpen] = createSignal(false);
  const [createRoleName, setCreateRoleName] = createSignal("");
  const [createBaseRole, setCreateBaseRole] = createSignal<"admin" | "editor" | "viewer">("editor");
  const [creatingRole, setCreatingRole] = createSignal(false);

  const [editRoleTarget, setEditRoleTarget] = createSignal<WorkspaceRole | null>(null);
  const [editRoleName, setEditRoleName] = createSignal("");
  const [editPermissions, setEditPermissions] = createSignal<PermissionOverrideMap>({});
  const [savingRole, setSavingRole] = createSignal(false);

  const [deleteRoleTarget, setDeleteRoleTarget] = createSignal<WorkspaceRole | null>(null);
  const [deletingRole, setDeletingRole] = createSignal(false);

  const openCreateRoleDialog = () => {
    options.setError(null);
    setCreateDialogOpen(true);
  };

  const closeCreateRoleDialog = () => {
    setCreateDialogOpen(false);
    setCreateRoleName("");
    setCreateBaseRole("editor");
  };

  const handleCreateRole = async () => {
    const name = createRoleName().trim();
    const id = workspaceId();
    if (!name || !id) return;

    setCreatingRole(true);
    options.setError(null);
    try {
      await workspacesApi.createRole(id, {
        name,
        base_role: createBaseRole(),
      });
      closeCreateRoleDialog();
      invalidateRoles();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to create role");
    } finally {
      setCreatingRole(false);
    }
  };

  const openEditRole = (role: WorkspaceRole) => {
    options.setError(null);
    setEditRoleTarget(role);
    setEditRoleName(role.name);

    const overrides: Record<string, boolean | null> = {};
    for (const permission of role.permissions ?? []) {
      overrides[permission.permission] = permission.granted;
    }
    setEditPermissions(overrides);
  };

  const closeEditRoleDialog = () => {
    setEditRoleTarget(null);
  };

  const handleSaveRole = async () => {
    const target = editRoleTarget();
    const id = workspaceId();
    if (!target || !id) return;

    setSavingRole(true);
    options.setError(null);
    try {
      const permissions = buildRolePermissions(editPermissions());

      await workspacesApi.updateRole(id, target.id, {
        name: editRoleName().trim() || undefined,
        permissions,
      });
      setEditRoleTarget(null);
      invalidateRoles();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to update role");
    } finally {
      setSavingRole(false);
    }
  };

  const openDeleteRoleDialog = (role: WorkspaceRole) => {
    options.setError(null);
    setDeleteRoleTarget(role);
  };

  const closeDeleteRoleDialog = () => {
    setDeleteRoleTarget(null);
  };

  const handleDeleteRole = async () => {
    const target = deleteRoleTarget();
    const id = workspaceId();
    if (!target || !id) return;

    setDeletingRole(true);
    options.setError(null);
    try {
      const response = (await workspacesApi.deleteRole(id, target.id)) as RoleDeleteResponse;
      setDeleteRoleTarget(null);
      invalidateRoles();
      queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });

      const count = response.invalidated_invitation_count;
      if (count > 0) {
        options.setInfo(`Role deleted. ${count} invitation(s) were invalidated.`);
      }
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to delete role");
    } finally {
      setDeletingRole(false);
    }
  };

  const handleSetDefault = async (roleId: WorkspaceRole["id"]) => {
    const id = workspaceId();
    if (!id) return;

    options.setError(null);
    try {
      await workspacesApi.updateRole(id, roleId, { is_default: true });
      invalidateRoles();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to set default role");
    }
  };

  const togglePermission = (permissionKey: string) => {
    setEditPermissions((current) => togglePermissionOverride(current, permissionKey));
  };

  const permissionState = (permissionKey: string): "default" | "granted" | "denied" => {
    return getPermissionOverrideState(editPermissions(), permissionKey);
  };

  const canEditPermission = (ceiling: string, roleBaseRole: string): boolean =>
    isAtOrAbove(roleBaseRole as BaseRole, ceiling as BaseRole);

  return {
    roles,
    createDialogOpen,
    openCreateRoleDialog,
    closeCreateRoleDialog,
    createRoleName,
    setCreateRoleName,
    createBaseRole,
    setCreateBaseRole,
    creatingRole,
    handleCreateRole,
    editRoleTarget,
    closeEditRoleDialog,
    editRoleName,
    setEditRoleName,
    savingRole,
    openEditRole,
    handleSaveRole,
    deleteRoleTarget,
    closeDeleteRoleDialog,
    deletingRole,
    openDeleteRoleDialog,
    handleDeleteRole,
    handleSetDefault,
    togglePermission,
    permissionState,
    canEditPermission,
  };
}

export type WorkspaceRoleManagementModel = ReturnType<typeof useWorkspaceRoleManagement>;
