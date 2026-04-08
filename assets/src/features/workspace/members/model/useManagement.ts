import { createSignal, type Accessor } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { type components, ApiError, workspacesApi } from "@/shared/api";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authState } from "@/entities/session";

type WorkspaceMember = components["schemas"]["MemberInfo"];
type RemoveMemberResponse = components["schemas"]["RemoveMemberResponse"];

interface UseWorkspaceMemberManagementOptions {
  workspaceId: Accessor<string | null | undefined>;
  setError: (value: string | null) => void;
  setInfo: (value: string | null) => void;
  triggerKekRotation: (rotationList: WorkspaceRotationInfo[]) => Promise<void>;
}

export function useWorkspaceMemberManagement(options: UseWorkspaceMemberManagementOptions) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const workspaceId = () => options.workspaceId();

  const members = createQuery(() => ({
    queryKey: ["workspace-members", workspaceId()],
    queryFn: () => workspacesApi.listMembers(workspaceId()!),
    enabled: !!workspaceId(),
  }));

  const currentUserId = () => authState()?.user.id;
  const memberPermissionDenied = () =>
    members.error instanceof ApiError && members.error.status === 403;

  const invalidateMemberViews = () => {
    const id = workspaceId();
    if (!id) return;

    queryClient.invalidateQueries({ queryKey: ["workspace", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-members", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });
    queryClient.invalidateQueries({ queryKey: ["workspaces"] });
  };

  const [removeTarget, setRemoveTarget] = createSignal<{
    user_id: WorkspaceMember["user_id"];
    name: WorkspaceMember["name"];
  } | null>(null);
  const [removing, setRemoving] = createSignal(false);

  const [roleChangeTarget, setRoleChangeTarget] = createSignal<{
    user_id: WorkspaceMember["user_id"];
    name: WorkspaceMember["name"];
    current_role_id: WorkspaceMember["role_id"];
  } | null>(null);
  const [selectedRoleId, setSelectedRoleId] = createSignal("");
  const [changingRole, setChangingRole] = createSignal(false);

  const openRemoveMemberDialog = (member: Pick<WorkspaceMember, "user_id" | "name">) => {
    options.setError(null);
    setRemoveTarget({
      user_id: member.user_id,
      name: member.name,
    });
  };

  const closeRemoveMemberDialog = () => {
    setRemoveTarget(null);
  };

  const openRoleChangeDialog = (member: Pick<WorkspaceMember, "user_id" | "name" | "role_id">) => {
    options.setError(null);
    setRoleChangeTarget({
      user_id: member.user_id,
      name: member.name,
      current_role_id: member.role_id,
    });
    setSelectedRoleId(member.role_id);
  };

  const closeRoleChangeDialog = () => {
    setRoleChangeTarget(null);
  };

  const handleRemoveMember = async () => {
    const target = removeTarget();
    const id = workspaceId();
    if (!target || !id) return;

    setRemoving(true);
    options.setError(null);
    try {
      const response = (await workspacesApi.removeMember(
        id,
        target.user_id,
      )) as RemoveMemberResponse;
      setRemoveTarget(null);

      const isSelfRemoval = target.user_id === currentUserId();
      if (isSelfRemoval) {
        setCurrentWorkspaceId(null);
        queryClient.invalidateQueries({ queryKey: ["workspaces"] });
        navigate("/dashboard");
        return;
      }

      invalidateMemberViews();

      const rotationList = response.workspaces_needing_kek_rotation ?? [];
      if (rotationList.length > 0) {
        try {
          await options.triggerKekRotation(rotationList);
          invalidateMemberViews();
        } catch {
          options.setInfo("Member removed. KEK rotation could not complete automatically.");
        }
      }
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to remove member");
    } finally {
      setRemoving(false);
    }
  };

  const handleChangeRole = async () => {
    const target = roleChangeTarget();
    const roleId = selectedRoleId();
    const id = workspaceId();
    if (!target || !roleId || !id) return;

    setChangingRole(true);
    options.setError(null);
    try {
      await workspacesApi.changeMemberRole(id, target.user_id, roleId);
      setRoleChangeTarget(null);
      invalidateMemberViews();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to change role");
    } finally {
      setChangingRole(false);
    }
  };

  return {
    members,
    currentUserId,
    memberPermissionDenied,
    removeTarget,
    removing,
    openRemoveMemberDialog,
    closeRemoveMemberDialog,
    handleRemoveMember,
    roleChangeTarget,
    selectedRoleId,
    setSelectedRoleId,
    changingRole,
    openRoleChangeDialog,
    closeRoleChangeDialog,
    handleChangeRole,
  };
}

export type WorkspaceMemberManagementModel = ReturnType<typeof useWorkspaceMemberManagement>;
