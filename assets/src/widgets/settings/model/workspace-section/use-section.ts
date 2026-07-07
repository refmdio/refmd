import { createEffect, createSignal } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import {
  updateWorkspace,
  updateWorkspaceFeatures,
  useWorkspaceDangerZone,
  useGuestInvitationManagement,
  useWorkspaceInvitationManagement,
  useWorkspaceMemberManagement,
  useWorkspacePermissions,
  useWorkspaceQuery,
  useWorkspaceRoleManagement,
} from "@/features/workspace";
import { createWorkspaceKekRotationTrigger } from "@/features/devices";
import { currentWorkspaceId } from "@/entities/workspace";

interface UseWorkspaceSectionOptions {
  closePluginRuntimeByWorkspace?: (workspaceId: string, reason?: string) => void | Promise<void>;
  releasePluginRuntimeWorkspaceRevocation?: (workspaceId: string) => void;
}

export function useWorkspaceSection(options: UseWorkspaceSectionOptions = {}) {
  const queryClient = useQueryClient();
  const wsId = () => currentWorkspaceId();

  const workspace = useWorkspaceQuery(wsId);

  const [error, setError] = createSignal<string | null>(null);
  const [info, setInfo] = createSignal<string | null>(null);
  const roleManagement = useWorkspaceRoleManagement({ workspaceId: wsId, setError, setInfo });
  const triggerKekRotation = createWorkspaceKekRotationTrigger();
  const memberManagement = useWorkspaceMemberManagement({
    workspaceId: wsId,
    setError,
    setInfo,
    triggerKekRotation,
    closePluginRuntimeByWorkspace: options.closePluginRuntimeByWorkspace,
    releasePluginRuntimeWorkspaceRevocation: options.releasePluginRuntimeWorkspaceRevocation,
  });
  const currentUserId = () => memberManagement.currentUserId();
  const dangerZone = useWorkspaceDangerZone({
    workspaceId: wsId,
    currentUserId,
    setError,
    triggerKekRotation,
    closePluginRuntimeByWorkspace: options.closePluginRuntimeByWorkspace,
    releasePluginRuntimeWorkspaceRevocation: options.releasePluginRuntimeWorkspaceRevocation,
  });
  const currentMember = () => {
    const fromList = memberManagement.members.data?.members?.find(
      (member) => member.user_id === currentUserId(),
    );
    if (fromList) return fromList;

    const currentWorkspace = workspace.data;
    if (currentWorkspace?.current_user_role_id) {
      return {
        role_id: currentWorkspace.current_user_role_id,
        base_role: currentWorkspace.current_user_base_role ?? "",
        user_id: currentUserId() ?? "",
      };
    }

    return undefined;
  };

  const isOwner = () => currentMember()?.base_role === "owner";
  const memberPermissionDenied = () => memberManagement.memberPermissionDenied();
  const permissions = useWorkspacePermissions({
    currentMember,
    roles: () => roleManagement.roles.data?.roles,
  });

  const refetchAll = () => {
    const id = wsId();
    void queryClient.invalidateQueries({ queryKey: ["workspace", id] });
    void queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    void queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });
    void queryClient.invalidateQueries({ queryKey: ["guest-invitations", id] });
    void queryClient.invalidateQueries({ queryKey: ["workspaces"] });
  };

  const [editingName, setEditingName] = createSignal(false);
  const [newName, setNewName] = createSignal("");
  const [editingDescription, setEditingDescription] = createSignal(false);
  const [newDescription, setNewDescription] = createSignal("");
  const [editingSlug, setEditingSlug] = createSignal(false);
  const [newSlug, setNewSlug] = createSignal("");
  const [updating, setUpdating] = createSignal(false);
  const [updatingFeatures, setUpdatingFeatures] = createSignal(false);
  const [publicAuthorName, setPublicAuthorName] = createSignal("");
  const [publicAuthorSlug, setPublicAuthorSlug] = createSignal("");
  const [publicAuthorBio, setPublicAuthorBio] = createSignal("");

  const handleUpdateField = async (
    payload: Parameters<typeof updateWorkspace>[1],
    closeEditor: () => void,
  ) => {
    const id = wsId();
    if (!id) return;

    setUpdating(true);
    setError(null);
    try {
      await updateWorkspace(id, payload);
      refetchAll();
      closeEditor();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setUpdating(false);
    }
  };

  const handleUpdateName = () => {
    const name = newName().trim();
    if (!name) return;
    return handleUpdateField({ name }, () => setEditingName(false));
  };

  const handleUpdateDescription = () => {
    return handleUpdateField({ description: newDescription().trim() || null }, () =>
      setEditingDescription(false),
    );
  };

  const handleUpdateSlug = () => {
    const slug = newSlug().trim();
    if (!slug) return;
    return handleUpdateField({ slug }, () => setEditingSlug(false));
  };

  const handleUpdateFeatures = async (payload: Parameters<typeof updateWorkspaceFeatures>[1]) => {
    const id = wsId();
    if (!id) return;

    setUpdatingFeatures(true);
    setError(null);
    try {
      await updateWorkspaceFeatures(id, payload);
      refetchAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update feature settings");
    } finally {
      setUpdatingFeatures(false);
    }
  };

  const handleUpdatePublicAuthor = () => {
    const bio = publicAuthorBio().trim();
    return handleUpdateFeatures({
      public_author_display_name: publicAuthorName().trim(),
      public_author_slug: publicAuthorSlug().trim(),
      ...(bio ? { public_author_bio: bio } : {}),
    });
  };

  const invitationManagement = useWorkspaceInvitationManagement({
    workspaceId: wsId,
    canManageInvitations: permissions.canInvite,
    assignableRoles: permissions.assignableRoles,
    defaultRoleAssignable: permissions.defaultRoleAssignable,
    setError,
  });

  const guestInvitationManagement = useGuestInvitationManagement({
    workspaceId: wsId,
    canManageGuestInvitations: permissions.canInviteGuests,
    canUpdateWorkspace: permissions.canUpdateWorkspace,
    guestInvitesEnabled: () => workspace.data?.guest_invites_enabled ?? false,
    guestMemberLimit: () => workspace.data?.guest_member_limit,
    setError,
    refetchWorkspace: refetchAll,
  });

  createEffect(() => {
    void [
      workspace.data?.id,
      workspace.data?.guest_invites_enabled,
      workspace.data?.guest_member_limit,
    ];
    guestInvitationManagement.syncSettings();
  });

  createEffect(() => {
    const profile = workspace.data?.public_author_profile;
    setPublicAuthorName(profile?.display_name ?? "");
    setPublicAuthorSlug(profile?.slug ?? "");
    setPublicAuthorBio(profile?.bio ?? "");
  });

  return {
    wsId,
    workspace,
    error,
    info,
    currentUserId,
    currentMember,
    isOwner,
    memberPermissionDenied,
    canUpdateWorkspace: permissions.canUpdateWorkspace,
    canManageFeatures: permissions.canManageFeatures,
    canInvite: permissions.canInvite,
    canInviteGuests: permissions.canInviteGuests,
    canChangeRole: permissions.canChangeRole,
    canRemoveMember: permissions.canRemoveMember,
    canManageRoles: permissions.canManageRoles,
    assignableRoles: permissions.assignableRoles,
    defaultRoleAssignable: permissions.defaultRoleAssignable,
    refetchAll,
    editingName,
    setEditingName,
    newName,
    setNewName,
    editingDescription,
    setEditingDescription,
    newDescription,
    setNewDescription,
    editingSlug,
    setEditingSlug,
    newSlug,
    setNewSlug,
    updating,
    updatingFeatures,
    publicAuthorName,
    setPublicAuthorName,
    publicAuthorSlug,
    setPublicAuthorSlug,
    publicAuthorBio,
    setPublicAuthorBio,
    handleUpdateName,
    handleUpdateDescription,
    handleUpdateSlug,
    handleUpdateFeatures,
    handleUpdatePublicAuthor,
    showDelete: dangerZone.showDelete,
    setShowDelete: dangerZone.setShowDelete,
    deleting: dangerZone.deleting,
    handleDelete: dangerZone.handleDelete,
    showLeave: dangerZone.showLeave,
    setShowLeave: dangerZone.setShowLeave,
    leaving: dangerZone.leaving,
    handleLeave: dangerZone.handleLeave,
    memberManagement,
    invitationManagement,
    guestInvitationManagement,
    roleManagement,
  };
}

export type WorkspaceSectionModel = ReturnType<typeof useWorkspaceSection>;
