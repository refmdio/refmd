/**
 * Workspace Section Model Hook
 *
 * Fetches members, roles, invitations and provides mutation actions.
 */

import { useCallback, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { workspaceApi, getApiErrorMessage } from '@/shared/api'
import { useWorkspaceSelection, useWorkspacesData, checkEffectivePermission } from '@/entities/workspace'
import { useAsyncData } from '@/shared/hooks/useAsyncData'
import { useAsyncAction } from '@/shared/hooks/useAsyncAction'
import { useAuthContext } from '@/shared/context'
import { useWorkspaceEvents } from '@/features/workspace-events'
export function useWorkspaceSection() {
  const { currentWorkspaceId } = useWorkspaceSelection()
  const { auth } = useAuthContext()
  const queryClient = useQueryClient()
  const workspaces = useWorkspacesData()
  const { lastInvitationAcceptedAt } = useWorkspaceEvents()
  const [refreshKey, setRefreshKey] = useState(0)
  const refresh = useCallback(() => setRefreshKey(k => k + 1), [])

  const roles = useAsyncData(
    () => workspaceApi.listRoles(currentWorkspaceId!),
    [currentWorkspaceId, refreshKey]
  )

  // Get user's role from workspace list (doesn't require member:list)
  const currentWorkspaceData = workspaces?.find(w => w.workspace.id === currentWorkspaceId)
  const userRole = currentWorkspaceData?.membership?.role
  const isOwner = userRole?.base_role === 'owner'

  // Find full role details (with overrides) from roles list
  const rolesList = roles.data?.roles ?? []

  // Derive member:list permission — gate the members fetch to avoid 403 for restricted roles
  const canListMembers = useMemo(() => {
    const roleId = userRole?.id
    if (roleId && rolesList.length > 0) {
      return checkEffectivePermission(rolesList, roleId, 'member:list')
    }
    // Fallback before roles are loaded: deny to prevent premature 403/404 API calls
    return false
  }, [userRole?.id, userRole?.base_role, rolesList])

  const members = useAsyncData(
    () => canListMembers ? workspaceApi.listMembers(currentWorkspaceId!) : Promise.resolve({ members: [] }),
    [currentWorkspaceId, refreshKey, canListMembers, lastInvitationAcceptedAt]
  )

  const permissions = useMemo(() => {
    const roleId = userRole?.id
    if (!roleId || rolesList.length === 0) {
      return {
        canInvite: false,
        canManageRoles: false,
        canUpdateWorkspace: false,
        canDeleteWorkspace: false,
        canChangeRoles: false,
        canRemoveMembers: false,
      }
    }
    return {
      canInvite: checkEffectivePermission(rolesList, roleId, 'member:invite'),
      canManageRoles: checkEffectivePermission(rolesList, roleId, 'role:manage'),
      canUpdateWorkspace: checkEffectivePermission(rolesList, roleId, 'workspace:update'),
      canDeleteWorkspace: checkEffectivePermission(rolesList, roleId, 'workspace:delete'),
      canChangeRoles: checkEffectivePermission(rolesList, roleId, 'member:change_role'),
      canRemoveMembers: checkEffectivePermission(rolesList, roleId, 'member:remove'),
    }
  }, [userRole?.id, rolesList])


  const invitations = useAsyncData(
    () => permissions.canInvite ? workspaceApi.listInvitations(currentWorkspaceId!) : Promise.resolve({ invitations: [] }),
    [currentWorkspaceId, refreshKey, permissions.canInvite, lastInvitationAcceptedAt]
  )

  const changeMemberRole = useAsyncAction(getApiErrorMessage)
  const removeMember = useAsyncAction(getApiErrorMessage)
  const revokeInvitation = useAsyncAction(getApiErrorMessage)
  const createRole = useAsyncAction(getApiErrorMessage)
  const updateRole = useAsyncAction(getApiErrorMessage)
  const deleteRole = useAsyncAction(getApiErrorMessage)
  const updateWorkspace = useAsyncAction(getApiErrorMessage)
  const deleteWorkspace = useAsyncAction(getApiErrorMessage)
  const leaveWorkspace = useAsyncAction(getApiErrorMessage)

  const handleChangeMemberRole = useCallback(
    async (userId: string, roleId: string) => {
      if (!currentWorkspaceId) return
      await changeMemberRole.execute(async () => {
        await workspaceApi.changeMemberRole(currentWorkspaceId, userId, { role_id: roleId })
        refresh()
      })
    },
    [currentWorkspaceId, changeMemberRole, refresh]
  )

  const handleRemoveMember = useCallback(
    async (userId: string) => {
      if (!currentWorkspaceId) return
      await removeMember.execute(async () => {
        await workspaceApi.removeMember(currentWorkspaceId, userId)
        refresh()
      })
    },
    [currentWorkspaceId, removeMember, refresh]
  )

  const handleRevokeInvitation = useCallback(
    async (invitationId: string) => {
      if (!currentWorkspaceId) return
      await revokeInvitation.execute(async () => {
        await workspaceApi.revokeInvitation(currentWorkspaceId, invitationId)
        refresh()
      })
    },
    [currentWorkspaceId, revokeInvitation, refresh]
  )

  const handleCreateRole = useCallback(
    async (name: string, baseRole: string, isDefault: boolean) => {
      if (!currentWorkspaceId) return
      await createRole.execute(async () => {
        await workspaceApi.createRole(currentWorkspaceId, { name, base_role: baseRole, is_default: isDefault })
        refresh()
      })
    },
    [currentWorkspaceId, createRole, refresh]
  )

  const handleUpdateRole = useCallback(
    async (roleId: string, updates: { name?: string; is_default?: boolean; permission_overrides?: Array<{ permission: string; granted: boolean }> }) => {
      if (!currentWorkspaceId) return
      await updateRole.execute(async () => {
        await workspaceApi.updateRole(currentWorkspaceId, roleId, updates)
        refresh()
      })
    },
    [currentWorkspaceId, updateRole, refresh]
  )

  const handleDeleteRole = useCallback(
    async (roleId: string) => {
      if (!currentWorkspaceId) return
      await deleteRole.execute(async () => {
        await workspaceApi.deleteRole(currentWorkspaceId, roleId)
        refresh()
      })
    },
    [currentWorkspaceId, deleteRole, refresh]
  )

  const handleUpdateWorkspace = useCallback(
    async (updates: { name?: string }) => {
      if (!currentWorkspaceId) return
      await updateWorkspace.execute(async () => {
        await workspaceApi.update(currentWorkspaceId, updates)
        await queryClient.invalidateQueries({ queryKey: ['workspaces'] })
        refresh()
      })
    },
    [currentWorkspaceId, updateWorkspace, queryClient, refresh]
  )

  const handleDeleteWorkspace = useCallback(
    async (): Promise<boolean> => {
      if (!currentWorkspaceId) return false
      return await deleteWorkspace.execute(async () => {
        await workspaceApi.delete(currentWorkspaceId)
        await queryClient.invalidateQueries({ queryKey: ['workspaces'] })
      })
    },
    [currentWorkspaceId, deleteWorkspace, queryClient]
  )

  const handleLeaveWorkspace = useCallback(
    async (): Promise<boolean> => {
      if (!currentWorkspaceId || !auth?.userId) return false
      return await leaveWorkspace.execute(async () => {
        await workspaceApi.removeMember(currentWorkspaceId, auth.userId)
        await queryClient.invalidateQueries({ queryKey: ['workspaces'] })
      })
    },
    [currentWorkspaceId, auth?.userId, leaveWorkspace, queryClient]
  )

  return {
    workspaceId: currentWorkspaceId,
    workspaceName: currentWorkspaceData?.workspace.name ?? undefined,
    currentUserId: auth?.userId ?? null,
    isOwner,
    permissions,
    members,
    roles,
    invitations,
    actions: {
      changeMemberRole: handleChangeMemberRole,
      changeMemberRoleError: changeMemberRole.error,
      removeMember: handleRemoveMember,
      removeMemberError: removeMember.error,
      revokeInvitation: handleRevokeInvitation,
      revokeInvitationError: revokeInvitation.error,
      createRole: handleCreateRole,
      updateRole: handleUpdateRole,
      deleteRole: handleDeleteRole,
      roleActionError: createRole.error || updateRole.error || deleteRole.error,
      updateWorkspace: handleUpdateWorkspace,
      deleteWorkspace: handleDeleteWorkspace,
      workspaceActionError: updateWorkspace.error || deleteWorkspace.error || leaveWorkspace.error,
      leaveWorkspace: handleLeaveWorkspace,
    },
    refresh,
  }
}
