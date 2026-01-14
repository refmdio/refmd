import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { Building2, Shield, Sparkles, Trash2, UserPlus, Users2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'

import { ApiError } from '@/shared/api'
import { setClientWorkspaceId } from '@/shared/api/client.config'
import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/shared/ui/select'
import { Switch } from '@/shared/ui/switch'
import { Textarea } from '@/shared/ui/textarea'

import { me as meApi, userKeys } from '@/entities/user'
import {
  listWorkspaceInvitations,
  listWorkspaceMembers,
  listWorkspaceRoles,
  workspaceKeys,
  type WorkspaceInvitationResponse,
  type WorkspaceMemberResponse,
  type WorkspaceRoleResponse,
} from '@/entities/workspace/api'

import { useAuthContext } from '@/features/auth'
import {
  acceptWorkspaceInvitationAction,
  DEFAULT_INVITE_ROLE,
  PERMISSION_GROUPS,
  buildSystemPermissionSet,
  computeOverrides,
  createWorkspaceAction,
  createWorkspaceRoleAction,
  deleteWorkspaceAction,
  deleteWorkspaceRoleAction,
  leaveWorkspaceAction,
  roleToPermissionSet,
  removeWorkspaceMemberAction,
  revokeWorkspaceInvitationAction,
  sendWorkspaceInvitationAction,
  updateWorkspaceMemberRoleAction,
  updateWorkspaceRoleAction,
  updateWorkspaceSettingsAction,
} from '@/features/workspaces'
import type { BaseRole, InviteRoleValue, SystemRole } from '@/features/workspaces'

function formatWorkspaceSecondaryText(workspace: ReturnType<typeof useAuthContext>['workspaces'][number]) {
  if (workspace.is_personal) {
    return 'Personal workspace'
  }
  const slug = workspace.slug ? `@${workspace.slug}` : null
  const role =
    workspace.role_kind === 'system'
      ? `${(workspace.system_role || 'member').replace(/^\w/, (ltr) => ltr.toUpperCase())} role`
      : 'Custom role'
  return slug ? `${slug} - ${role}` : role
}

type RoleFormState = {
  name: string
  description: string
  baseRole: BaseRole
  priority: number
  permissions: Set<string>
}

function defaultRoleForm(): RoleFormState {
  return {
    name: '',
    description: '',
    baseRole: 'editor',
    priority: 0,
    permissions: buildSystemPermissionSet('editor'),
  }
}

function roleToFormState(role: WorkspaceRoleResponse): RoleFormState {
  return {
    name: role.name,
    description: role.description ?? '',
    baseRole: role.base_role as BaseRole,
    priority: role.priority ?? 0,
    permissions: roleToPermissionSet(role),
  }
}

type WorkspaceSearch = {
  token?: string | null
}

export default function WorkspacesPage() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { user, workspaces, activeWorkspaceId, activeWorkspace, permissions, switchWorkspace } = useAuthContext()
  const workspaceSearch = useSearch({ from: '/(app)/workspaces' }) as WorkspaceSearch
  const [createOpen, setCreateOpen] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createDescription, setCreateDescription] = useState('')
  const [creating, setCreating] = useState(false)
  const [switchingId, setSwitchingId] = useState<string | null>(null)
  const [inviteOpen, setInviteOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<InviteRoleValue>(DEFAULT_INVITE_ROLE)
  const [inviting, setInviting] = useState(false)
  const [acceptingInvite, setAcceptingInvite] = useState(false)
  const inviteToken = typeof workspaceSearch?.token === 'string' && workspaceSearch.token.length > 0 ? workspaceSearch.token : null
  const [memberRoleUpdating, setMemberRoleUpdating] = useState<string | null>(null)
  const [memberRemovingId, setMemberRemovingId] = useState<string | null>(null)
  const [roleDialogOpen, setRoleDialogOpen] = useState(false)
  const [roleDialogMode, setRoleDialogMode] = useState<'create' | 'edit'>('create')
  const [roleForm, setRoleForm] = useState<RoleFormState>(defaultRoleForm())
  const [editingRole, setEditingRole] = useState<WorkspaceRoleResponse | null>(null)
  const [roleSaving, setRoleSaving] = useState(false)
  const [roleDeleting, setRoleDeleting] = useState(false)
  const [settingsName, setSettingsName] = useState(activeWorkspace?.name ?? '')
  const [settingsDescription, setSettingsDescription] = useState(activeWorkspace?.description ?? '')
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [deletingWorkspace, setDeletingWorkspace] = useState(false)
  const [revokingInvitationId, setRevokingInvitationId] = useState<string | null>(null)
  const [leavingWorkspaceId, setLeavingWorkspaceId] = useState<string | null>(null)

  const workspaceId = activeWorkspaceId
  const workspaceName = activeWorkspace?.name ?? 'Workspace'
  const canViewMembers = permissions.includes('member:view')
  const canManageMembers = permissions.includes('member:update_role')
  const canInviteMembers = permissions.includes('member:invite')
  const canRemoveMembers = permissions.includes('member:remove')
  const canManageRoles = permissions.includes('member:update_role')
  const canFetchRoles = canManageRoles || canInviteMembers || canViewMembers
  const canViewInvitations = canInviteMembers
  const canEditWorkspace = permissions.includes('workspace:update_settings')
  const canDeleteWorkspace = permissions.includes('workspace:delete')
  const hasActiveWorkspace = Boolean(workspaceId)

  const membersQuery = useQuery({
    queryKey: workspaceKeys.members(workspaceId),
    enabled: !!workspaceId && canViewMembers,
    queryFn: async () => {
      if (!workspaceId) return [] as WorkspaceMemberResponse[]
      return listWorkspaceMembers(workspaceId)
    },
  })

  const rolesQuery = useQuery({
    queryKey: workspaceKeys.roles(workspaceId),
    enabled: !!workspaceId && canFetchRoles,
    queryFn: async () => {
      if (!workspaceId) return [] as WorkspaceRoleResponse[]
      return listWorkspaceRoles(workspaceId)
    },
  })

  const invitationsQuery = useQuery({
    queryKey: workspaceKeys.invitations(workspaceId),
    enabled: !!workspaceId && canViewInvitations,
    queryFn: async () => {
      if (!workspaceId) return [] as WorkspaceInvitationResponse[]
      return listWorkspaceInvitations(workspaceId)
    },
  })

  const members = (membersQuery.data ?? []) as WorkspaceMemberResponse[]
  const roles = (rolesQuery.data ?? []) as WorkspaceRoleResponse[]
  const invitations = (invitationsQuery.data ?? []) as WorkspaceInvitationResponse[]
  const inviteBaseUrl =
    typeof window !== 'undefined' ? `${window.location.origin}/workspaces?token=` : '/workspaces?token='
  const pendingInvitations = useMemo(() => {
    return invitations.filter((invitation) => {
      if (invitation.accepted_at || invitation.revoked_at) {
        return false
      }
      if (!invitation.expires_at) {
        return true
      }
      const expiresAt = new Date(invitation.expires_at).getTime()
      return Number.isFinite(expiresAt) && expiresAt > Date.now()
    })
  }, [invitations])
  const customRoles = useMemo(() => roles.slice().sort((a, b) => a.priority - b.priority), [roles])
  const roleOptions = useMemo(() => {
    const system = ['owner', 'admin', 'editor', 'viewer'].map((role) => ({
      label: role.replace(/^[a-z]/, (ltr) => ltr.toUpperCase()),
      value: `system:${role}`,
    }))
    const custom = customRoles.map((role) => ({
      label: role.name,
      value: `custom:${role.id}`,
    }))
    return [...system, ...custom]
  }, [customRoles])

  useEffect(() => {
    if (inviteRole.startsWith('custom:')) {
      const roleId = inviteRole.split(':')[1]
      if (!customRoles.some((role) => role.id === roleId)) {
        setInviteRole(DEFAULT_INVITE_ROLE)
      }
    }
  }, [customRoles, inviteRole])

  useEffect(() => {
    if (!roleDialogOpen) return
    if (editingRole) {
      setRoleForm(roleToFormState(editingRole))
    } else {
      setRoleForm(defaultRoleForm())
    }
  }, [roleDialogOpen, editingRole])

  useEffect(() => {
    setSettingsName(activeWorkspace?.name ?? '')
    setSettingsDescription(activeWorkspace?.description ?? '')
  }, [activeWorkspace?.id, activeWorkspace?.name, activeWorkspace?.description])

  const ownerCount = useMemo(
    () => workspaces.filter((ws) => ws.system_role === 'owner').length,
    [workspaces],
  )

  const clearInviteToken = () => {
    navigate({
      to: '/workspaces',
      search: (prev: Record<string, unknown>) => {
        const next = { ...prev }
        delete next.token
        return next
      },
    })
  }

  const handleMemberRoleChange = async (memberId: string, selection: string) => {
    if (!workspaceId) return
    setMemberRoleUpdating(memberId)
    const [kind, value] = selection.split(':') as ['system' | 'custom', string]
    const roleSelection =
      kind === 'custom'
        ? { kind: 'custom' as const, customRoleId: value }
        : { kind: 'system' as const, systemRole: value as SystemRole }
    try {
      await updateWorkspaceMemberRoleAction({ workspaceId, memberId, selection: roleSelection })
      if (memberId === user?.id) {
        const updated = await meApi()
        queryClient.setQueryData(userKeys.me(), updated)
      }
      toast.success('Member updated')
      await membersQuery.refetch()
    } catch (error) {
      console.error('[workspaces] update member role failed', error)
      toast.error('Failed to update member role')
    } finally {
      setMemberRoleUpdating(null)
    }
  }

  const handleCreateWorkspace = async () => {
    if (!createName.trim()) {
      toast.error('Workspace name is required')
      return
    }
    setCreating(true)
    try {
      const workspace = await createWorkspaceAction({ name: createName, description: createDescription })
      const workspaceId = workspace?.id
      if (workspaceId) {
        setClientWorkspaceId(workspaceId)
      }
      const updated = await meApi()
      queryClient.setQueryData(userKeys.me(), updated)
      toast.success('Workspace created')
      setCreateName('')
      setCreateDescription('')
      setCreateOpen(false)
    } catch (error) {
      console.error('[workspaces] create failed', error)
      const message = error instanceof Error ? error.message : 'Failed to create workspace'
      toast.error(message)
    } finally {
      setCreating(false)
    }
  }

  const handleSaveWorkspaceSettings = async () => {
    if (!workspaceId) return
    if (!canEditWorkspace) {
      toast.error('You do not have permission to update this workspace')
      return
    }
    if (!settingsName.trim()) {
      toast.error('Workspace name is required')
      return
    }
    setSettingsSaving(true)
    try {
      await updateWorkspaceSettingsAction({ workspaceId, name: settingsName, description: settingsDescription })
      const updated = await meApi()
      queryClient.setQueryData(userKeys.me(), updated)
      await Promise.all([
        membersQuery.refetch(),
        rolesQuery.refetch(),
        invitationsQuery.refetch(),
      ])
      toast.success('Workspace updated')
    } catch (error) {
      console.error('[workspaces] update settings failed', error)
      const message = error instanceof Error ? error.message : 'Failed to update workspace'
      toast.error(message)
    } finally {
      setSettingsSaving(false)
    }
  }

  const handleDeleteWorkspace = async () => {
    if (!workspaceId) return
    if (!canDeleteWorkspace) {
      toast.error('You do not have permission to delete this workspace')
      return
    }
    if (!window.confirm('Are you sure you want to delete this workspace? This action cannot be undone.')) {
      return
    }
    setDeletingWorkspace(true)
    try {
      await deleteWorkspaceAction(workspaceId)
      toast.success('Workspace deleted')
      const updated = await meApi()
      queryClient.clear()
      queryClient.setQueryData(userKeys.me(), updated)
    } catch (error) {
      console.error('[workspaces] delete workspace failed', error)
      let message = error instanceof Error ? error.message : 'Failed to delete workspace'
      if (error instanceof ApiError) {
        if (error.status === 400) {
          message = 'Personal workspaces cannot be deleted'
        } else if (error.status === 409) {
          message = 'Cannot delete while members have it set as their default workspace'
        }
      }
      toast.error(message)
    } finally {
      setDeletingWorkspace(false)
    }
  }

  const handleSendInvite = async () => {
    if (!workspaceId) {
      toast.error('Select an active workspace first')
      return
    }
    if (!canInviteMembers) {
      toast.error('You do not have permission to invite members')
      return
    }
    if (!inviteEmail.trim()) {
      toast.error('Please enter an email address')
      return
    }
    const [roleKind, roleValue] = inviteRole.split(':') as ['system' | 'custom', string]
    setInviting(true)
    try {
      if (roleKind === 'custom' && !roleValue) {
        throw new Error('Select a valid custom role')
      }
      const selection =
        roleKind === 'custom'
          ? { kind: 'custom' as const, customRoleId: roleValue }
          : { kind: 'system' as const, systemRole: roleValue as SystemRole }
      await sendWorkspaceInvitationAction({ workspaceId, email: inviteEmail.trim(), selection })
      toast.success('Invitation sent')
      setInviteEmail('')
      setInviteRole(DEFAULT_INVITE_ROLE)
      setInviteOpen(false)
      await invitationsQuery.refetch()
    } catch (error) {
      console.error('[workspaces] invite failed', error)
      const message = error instanceof Error ? error.message : 'Failed to send invitation'
      toast.error(message)
    } finally {
      setInviting(false)
    }
  }

  const copyInvitationLink = async (token: string) => {
    try {
      await navigator.clipboard.writeText(`${inviteBaseUrl}${token}`)
      toast.success('Invitation link copied')
    } catch (error) {
      console.error('[workspaces] copy invitation link failed', error)
      toast.error('Failed to copy link')
    }
  }

  const handleRevokeInvitation = async (invitationId: string) => {
    if (!workspaceId) return
    if (!canInviteMembers) {
      toast.error('You do not have permission to revoke invitations')
      return
    }
    if (!window.confirm('Cancel this invitation? Invited users will no longer be able to join.')) {
      return
    }
    setRevokingInvitationId(invitationId)
    try {
      await revokeWorkspaceInvitationAction(workspaceId, invitationId)
      toast.success('Invitation revoked')
      await invitationsQuery.refetch()
    } catch (error) {
      console.error('[workspaces] revoke invitation failed', error)
      const message = error instanceof Error ? error.message : 'Failed to revoke invitation'
      toast.error(message)
    } finally {
      setRevokingInvitationId(null)
    }
  }

  const handleRemoveMember = async (memberId: string) => {
    if (!workspaceId || !canRemoveMembers) return
    if (memberId === user?.id) {
      toast.error('You cannot remove yourself')
      return
    }
    if (!window.confirm('Are you sure you want to remove this member?')) {
      return
    }
    setMemberRemovingId(memberId)
    try {
      await removeWorkspaceMemberAction(workspaceId, memberId)
      toast.success('Member removed')
      await membersQuery.refetch()
    } catch (error) {
      console.error('[workspaces] remove member failed', error)
      const message = error instanceof Error ? error.message : 'Failed to remove member'
      toast.error(message)
    } finally {
      setMemberRemovingId(null)
    }
  }

  const handleLeaveWorkspace = async (workspaceId: string) => {
    if (!user) return
    if (workspaceId === user.id) {
      toast.error('Personal workspaces cannot be left')
      return
    }
    if (!window.confirm('Leave this workspace? You will lose access to its documents.')) {
      return
    }
    setLeavingWorkspaceId(workspaceId)
    try {
      await leaveWorkspaceAction(workspaceId)
      const updated = await meApi()
      queryClient.setQueryData(userKeys.me(), updated)
      queryClient.removeQueries({ queryKey: workspaceKeys.members(workspaceId) })
      queryClient.removeQueries({ queryKey: workspaceKeys.roles(workspaceId) })
      queryClient.removeQueries({ queryKey: workspaceKeys.invitations(workspaceId) })
      toast.success('You left the workspace')
    } catch (error) {
      console.error('[workspaces] leave workspace failed', error)
      let message = error instanceof Error ? error.message : 'Failed to leave workspace'
      if (error instanceof ApiError && error.status === 400) {
        message = 'This workspace cannot be left right now'
      }
      toast.error(message)
    } finally {
      setLeavingWorkspaceId(null)
    }
  }

  const handleAcceptInvite = async () => {
    if (!inviteToken) return
    setAcceptingInvite(true)
    try {
      await acceptWorkspaceInvitationAction(inviteToken)
      const updated = await meApi()
      queryClient.setQueryData(userKeys.me(), updated)
      toast.success('Invitation accepted')
      clearInviteToken()
      await Promise.all([membersQuery.refetch(), invitationsQuery.refetch()])
    } catch (error) {
      console.error('[workspaces] accept invite failed', error)
      const message = error instanceof Error ? error.message : 'Failed to accept invitation'
      toast.error(message)
    } finally {
      setAcceptingInvite(false)
    }
  }

  const handleSwitchWorkspace = async (workspaceId: string) => {
    if (workspaceId === activeWorkspaceId) {
      return
    }
    setSwitchingId(workspaceId)
    try {
      await switchWorkspace(workspaceId)
      toast.success('Workspace switched')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: workspaceKeys.members(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: workspaceKeys.roles(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: workspaceKeys.invitations(workspaceId) }),
      ])
    } catch (error) {
      console.error('[workspaces] switch failed', error)
      const message = error instanceof Error ? error.message : 'Failed to switch workspace'
      toast.error(message)
    } finally {
      setSwitchingId(null)
    }
  }

  const openCreateRoleDialog = () => {
    setRoleDialogMode('create')
    setEditingRole(null)
    setRoleDialogOpen(true)
  }

  const openEditRoleDialog = (role: WorkspaceRoleResponse) => {
    setRoleDialogMode('edit')
    setEditingRole(role)
    setRoleDialogOpen(true)
  }

  const handlePermissionToggle = (permission: string, allowed: boolean) => {
    setRoleForm((prev) => {
      const next = new Set(prev.permissions)
      if (allowed) {
        next.add(permission)
      } else {
        next.delete(permission)
      }
      return { ...prev, permissions: next }
    })
  }

  const handleSubmitRole = async () => {
    if (!workspaceId) return
    if (!roleForm.name.trim()) {
      toast.error('Role name is required')
      return
    }
    setRoleSaving(true)
    try {
      const overrides = computeOverrides(roleForm.baseRole, roleForm.permissions)
      if (roleDialogMode === 'create') {
        await createWorkspaceRoleAction({
          workspaceId,
          name: roleForm.name,
          baseRole: roleForm.baseRole,
          description: roleForm.description,
          priority: roleForm.priority,
          overrides,
        })
        toast.success('Role created')
      } else if (editingRole) {
        await updateWorkspaceRoleAction({
          workspaceId,
          roleId: editingRole.id,
          name: roleForm.name,
          baseRole: roleForm.baseRole,
          description: roleForm.description,
          priority: roleForm.priority,
          overrides,
        })
        toast.success('Role updated')
      }
      setRoleDialogOpen(false)
      setEditingRole(null)
      await rolesQuery.refetch()
    } catch (error) {
      console.error('[workspaces] save role failed', error)
      const message = error instanceof Error ? error.message : 'Failed to save role'
      toast.error(message)
    } finally {
      setRoleSaving(false)
    }
  }

  const handleDeleteRole = async () => {
    if (!workspaceId || !editingRole) return
    setRoleDeleting(true)
    try {
      await deleteWorkspaceRoleAction(workspaceId, editingRole.id)
      toast.success('Role deleted')
      setRoleDialogOpen(false)
      setEditingRole(null)
      await rolesQuery.refetch()
    } catch (error) {
      console.error('[workspaces] delete role failed', error)
      const message = error instanceof Error ? error.message : 'Failed to delete role'
      toast.error(message)
    } finally {
      setRoleDeleting(false)
    }
  }

  const canManageCurrentWorkspace = hasActiveWorkspace

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-10 px-4 pb-20 pt-10 sm:px-6 md:px-8">
        {inviteToken && (
          <div className="rounded-3xl border border-primary/40 bg-primary/5 p-5 shadow-sm">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-sm font-semibold text-primary">Workspace invitation detected</p>
                <p className="text-sm text-muted-foreground">[ {inviteToken.slice(0, 8)}... ]</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={handleAcceptInvite} disabled={acceptingInvite}>
                  {acceptingInvite ? 'Accepting...' : 'Accept invitation'}
                </Button>
                <Button variant="ghost" onClick={clearInviteToken}>
                  Dismiss
                </Button>
              </div>
            </div>
          </div>
        )}

        <section className="rounded-3xl border border-border/60 p-6 shadow-lg backdrop-blur md:p-8">
          <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="space-y-2">
              <Badge variant="secondary" className="w-fit rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide">
                Workspaces
              </Badge>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                Manage your collaborative spaces
              </h1>
              <p className="text-sm text-muted-foreground">
                View every workspace you belong to, switch contexts, and manage members & roles.
              </p>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row">
              <Button className="rounded-2xl px-4 py-5 text-base" onClick={() => setCreateOpen(true)}>
                <Sparkles className="mr-2 h-4 w-4" />
                New workspace
              </Button>
              <Button
                variant="outline"
                className="rounded-2xl px-4 py-5 text-base"
                onClick={() => setInviteOpen(true)}
                disabled={!canInviteMembers}
              >
                <Users2 className="mr-2 h-4 w-4" />
                Invite members
              </Button>
            </div>
          </div>
          <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-2">
            <div className="rounded-2xl border border-border/70 bg-muted/20 p-5">
              <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground/80">Total</p>
              <p className="mt-2 text-3xl font-semibold text-foreground">{workspaces.length}</p>
              <p className="text-sm text-muted-foreground">Workspaces you can access</p>
            </div>
            <div className="rounded-2xl border border-border/70 bg-muted/20 p-5">
              <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground/80">Owners</p>
              <p className="mt-2 text-3xl font-semibold text-foreground">{ownerCount}</p>
              <p className="text-sm text-muted-foreground">Where you hold owner rights</p>
            </div>
          </div>
        </section>

        <section className="rounded-3xl border border-border/60 p-6 shadow-lg backdrop-blur md:p-8">
          <div className="space-y-2">
            <Badge variant="outline" className="w-fit rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide">
              Settings
            </Badge>
            <h2 className="text-xl font-semibold">Workspace settings</h2>
            <p className="text-sm text-muted-foreground">Update the name or description of the currently active workspace.</p>
          </div>
          {workspaceId ? (
            <div className="mt-6 space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="workspace-name">Name</Label>
                  <Input
                    id="workspace-name"
                    value={settingsName}
                    onChange={(event) => setSettingsName(event.target.value)}
                    disabled={!canEditWorkspace}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Slug</Label>
                  <Input value={activeWorkspace?.slug ?? '—'} disabled readOnly />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="workspace-description">Description</Label>
                <Textarea
                  id="workspace-description"
                  value={settingsDescription}
                  onChange={(event) => setSettingsDescription(event.target.value)}
                  placeholder="Add a short summary"
                  disabled={!canEditWorkspace}
                />
              </div>
              <div className="flex flex-wrap gap-3">
                <Button onClick={handleSaveWorkspaceSettings} disabled={!canEditWorkspace || settingsSaving}>
                  {settingsSaving ? 'Saving…' : 'Save changes'}
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  onClick={handleDeleteWorkspace}
                  disabled={!canDeleteWorkspace || deletingWorkspace}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  {deletingWorkspace ? 'Deleting…' : 'Delete workspace'}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Deleting a workspace is only possible when no member has it set as their default workspace.
              </p>
              {!canEditWorkspace && (
                <p className="text-xs text-muted-foreground">
                  You do not have permission to edit these settings. Contact a workspace admin or owner.
                </p>
              )}
              {!canDeleteWorkspace && (
                <p className="text-xs text-muted-foreground">
                  You also need the delete permission to remove this workspace.
                </p>
              )}
            </div>
          ) : (
            <p className="mt-4 text-sm text-muted-foreground">No active workspace.</p>
          )}
        </section>

        <section className="space-y-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div className="space-y-1">
              <h2 className="flex items-center gap-2 text-lg font-semibold text-foreground">
                <Building2 className="h-5 w-5 text-primary" />
                Your workspaces
              </h2>
              <p className="text-sm text-muted-foreground">
                Switch contexts or review membership details.
              </p>
            </div>
            <Badge variant="secondary" className="self-start rounded-full px-3 py-1">
              {workspaces.length}
            </Badge>
          </div>
          {workspaces.length === 0 ? (
            <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-muted-foreground/40 bg-muted/20 px-6 py-10 text-center text-sm text-muted-foreground">
              <Sparkles className="h-6 w-6 text-primary" />
              <div className="space-y-1">
                <p className="text-base font-medium text-foreground">No workspaces yet</p>
                <p>Create your first workspace to get started.</p>
              </div>
              <Button onClick={() => setCreateOpen(true)}>Create workspace</Button>
            </div>
          ) : (
            <div className="space-y-4">
              {workspaces.map((workspace) => {
                const isActive = workspace.id === activeWorkspaceId
                const isSwitching = switchingId === workspace.id
                const canLeave = !workspace.is_personal && workspace.id !== user?.id
                const leaving = leavingWorkspaceId === workspace.id
                return (
                  <div
                    key={workspace.id}
                    className={cn(
                      'rounded-3xl border border-border/60 bg-card p-6 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-primary/40',
                      isActive && 'border-primary/40 bg-primary/5',
                    )}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground/80">Workspace</p>
                        <h3 className="text-xl font-semibold text-foreground">{workspace.name}</h3>
                        <p className="text-sm text-muted-foreground">{formatWorkspaceSecondaryText(workspace)}</p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        {workspace.is_personal && <Badge variant="outline">Personal</Badge>}
                        {isActive && <Badge>Active</Badge>}
                        {workspace.is_default && (
                          <Badge variant="secondary" className="text-xs">
                            Default
                          </Badge>
                        )}
                        <Button
                          variant={isActive ? 'secondary' : 'outline'}
                          size="sm"
                          className="rounded-full"
                          disabled={isSwitching || isActive}
                          onClick={() => handleSwitchWorkspace(workspace.id)}
                        >
                          {isSwitching ? 'Switching…' : isActive ? 'Current' : 'Switch'}
                        </Button>
                        {canLeave && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="rounded-full text-destructive hover:text-destructive"
                            disabled={leaving}
                            onClick={() => handleLeaveWorkspace(workspace.id)}
                          >
                            {leaving ? 'Leaving…' : 'Leave'}
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>

        {canManageCurrentWorkspace && (
          <section className="space-y-8">
            {canViewMembers ? (
              <div className="rounded-3xl border border-border/70 p-6 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="flex items-center gap-2 text-lg font-semibold text-foreground">
                      <Users2 className="h-5 w-5 text-primary" /> Members
                    </h3>
                    <p className="text-sm text-muted-foreground">Manage who has access to {workspaceName}.</p>
                  </div>
                  {canInviteMembers && (
                    <Button variant="outline" className="rounded-full" onClick={() => setInviteOpen(true)}>
                      <UserPlus className="mr-2 h-4 w-4" /> Invite
                    </Button>
                  )}
                </div>
                {membersQuery.isLoading ? (
                  <div className="mt-4 space-y-2">
                    {[0, 1, 2].map((idx) => (
                      <div key={idx} className="h-16 animate-pulse rounded-2xl bg-muted/40" />
                    ))}
                  </div>
                ) : members.length === 0 ? (
                  <p className="mt-4 text-sm text-muted-foreground">No members yet.</p>
                ) : (
                  <div className="mt-4 space-y-3">
                    {members.map((member) => {
                      const roleValue = member.role_kind === 'system'
                        ? `system:${member.system_role ?? 'viewer'}`
                        : `custom:${member.custom_role_id}`
                      const roleLabelText = member.role_kind === 'system'
                        ? (member.system_role || 'member').replace(/^[a-z]/, (ltr) => ltr.toUpperCase())
                        : customRoles.find((role) => role.id === member.custom_role_id)?.name || 'Custom'
                      const disableSelect = !canManageMembers || member.user_id === user?.id || member.system_role === 'owner'
                      const showRemoveButton = canRemoveMembers && member.user_id !== user?.id
                      const removeDisabled = member.workspace_id === member.user_id
                      const removing = memberRemovingId === member.user_id
                      return (
                        <div
                          key={member.user_id}
                          className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border/60 bg-card/70 p-4"
                        >
                          <div>
                            <p className="text-sm font-semibold text-foreground">{member.name}</p>
                            <p className="text-xs text-muted-foreground">{member.email}</p>
                            <div className="mt-1 flex flex-wrap items-center gap-2">
                              <Badge variant="outline" className="text-xs">
                                {roleLabelText}
                              </Badge>
                              {member.is_default && <Badge variant="secondary">Default</Badge>}
                            </div>
                          </div>
                          {(canManageMembers || showRemoveButton) && (
                            <div className="flex flex-wrap items-center gap-2">
                              {canManageMembers && (
                                <Select
                                  value={roleValue}
                                  onValueChange={(value) => handleMemberRoleChange(member.user_id, value)}
                                  disabled={disableSelect || memberRoleUpdating === member.user_id}
                                >
                                  <SelectTrigger className="w-[200px]">
                                    <SelectValue placeholder="Select role" />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {roleOptions.map((option) => (
                                      <SelectItem key={option.value} value={option.value}>
                                        {option.label}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                              )}
                              {showRemoveButton && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="rounded-full text-destructive hover:text-destructive"
                                  disabled={removeDisabled || removing}
                                  onClick={() => handleRemoveMember(member.user_id)}
                                >
                                  {removing ? (
                                    'Removing…'
                                  ) : (
                                    <>
                                      <Trash2 className="mr-1 h-4 w-4" /> Remove
                                    </>
                                  )}
                                </Button>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            ) : (
              <div className="rounded-3xl border border-border/70 p-6 text-sm text-muted-foreground">
                You do not have permission to view members in this workspace.
              </div>
            )}

            {canViewInvitations && (
              <div className="rounded-3xl border border-border/70 p-6 shadow-sm">
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h3 className="flex items-center gap-2 text-lg font-semibold text-foreground">
                      <Shield className="h-5 w-5 text-primary" /> Invitations
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Share invite links or review pending requests for {workspaceName}.
                    </p>
                  </div>
                  {canInviteMembers && (
                    <Button variant="outline" className="rounded-full" onClick={() => setInviteOpen(true)}>
                      Invite someone new
                    </Button>
                  )}
                </div>
                {invitationsQuery.isLoading ? (
                  <div className="mt-4 space-y-2">
                    {[0, 1, 2].map((idx) => (
                      <div key={idx} className="h-14 animate-pulse rounded-2xl bg-muted/30" />
                    ))}
                  </div>
                ) : invitationsQuery.isError ? (
                  <p className="mt-4 text-sm text-destructive">
                    {invitationsQuery.error instanceof Error
                      ? invitationsQuery.error.message
                      : 'Failed to load invitations'}
                  </p>
                ) : pendingInvitations.length === 0 ? (
                  <p className="mt-4 text-sm text-muted-foreground">No active invitations.</p>
                ) : (
                  <div className="mt-4 space-y-3">
                    {pendingInvitations.map((invitation) => {
                      const customRoleName = customRoles.find((role) => role.id === invitation.custom_role_id)?.name
                      const roleLabel =
                        invitation.role_kind === 'system'
                          ? `Role: ${(invitation.system_role ?? 'viewer').replace(/^[a-z]/, (ltr) => ltr.toUpperCase())}`
                          : `Role: ${customRoleName ?? 'Custom role'}`
                      return (
                        <div
                          key={invitation.id}
                          className="flex flex-col gap-3 rounded-2xl border border-border/50 bg-background/80 p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between"
                        >
                          <div className="space-y-1">
                            <p className="text-sm font-semibold text-foreground">{invitation.email}</p>
                            <p className="text-xs text-muted-foreground">{roleLabel}</p>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <code className="rounded-xl bg-muted/60 px-3 py-1 text-xs text-muted-foreground">{invitation.token.slice(0, 8)}…</code>
                            <Button size="sm" variant="secondary" onClick={() => copyInvitationLink(invitation.token)}>
                              Copy link
                            </Button>
                            {canInviteMembers && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="text-destructive hover:text-destructive"
                                onClick={() => handleRevokeInvitation(invitation.id)}
                                disabled={revokingInvitationId === invitation.id}
                              >
                                <Trash2 className="mr-2 h-3.5 w-3.5" />
                                {revokingInvitationId === invitation.id ? 'Revoking…' : 'Revoke'}
                              </Button>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )}

            {canManageRoles ? (
              <div className="rounded-3xl border border-border/70 p-6 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="flex items-center gap-2 text-lg font-semibold text-foreground">
                      <Shield className="h-5 w-5 text-primary" /> Custom roles
                    </h3>
                    <p className="text-sm text-muted-foreground">Tailor permissions beyond the built-in system roles.</p>
                  </div>
                  <Button className="rounded-full" onClick={openCreateRoleDialog}>
                    <Sparkles className="mr-2 h-4 w-4" /> New role
                  </Button>
                </div>
                {rolesQuery.isLoading ? (
                  <div className="mt-4 space-y-2">
                    {[0, 1].map((idx) => (
                      <div key={idx} className="h-20 animate-pulse rounded-2xl bg-muted/40" />
                    ))}
                  </div>
                ) : rolesQuery.isError ? (
                  <p className="mt-4 text-sm text-destructive">
                    {rolesQuery.error instanceof ApiError && rolesQuery.error.status === 403
                      ? 'You do not have permission to view custom roles.'
                      : rolesQuery.error instanceof Error
                        ? rolesQuery.error.message
                        : 'Failed to load custom roles.'}
                  </p>
                ) : customRoles.length === 0 ? (
                  <p className="mt-4 text-sm text-muted-foreground">No custom roles yet.</p>
                ) : (
                  <div className="mt-4 space-y-3">
                    {customRoles.map((role) => {
                      const permissionCount = roleToPermissionSet(role).size
                      return (
                        <div
                          key={role.id}
                          className="rounded-2xl border border-border/60 bg-card/70 p-4"
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <p className="text-sm font-semibold text-foreground">{role.name}</p>
                              <p className="text-xs text-muted-foreground">
                                Based on {role.base_role.toUpperCase()} • {permissionCount} permissions
                              </p>
                              {role.description && (
                                <p className="mt-1 text-xs text-muted-foreground">{role.description}</p>
                              )}
                            </div>
                            <div className="flex flex-wrap gap-2">
                              <Button variant="outline" size="sm" className="rounded-full" onClick={() => openEditRoleDialog(role)}>
                                Edit
                              </Button>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            ) : null}

          </section>
        )}
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className={cn('sm:max-w-md', overlayPanelClass)}>
          <DialogHeader>
            <DialogTitle>Create a workspace</DialogTitle>
            <DialogDescription>
              Workspaces isolate documents, members, and permissions. You can invite teammates after creation.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="workspace-name">Name</Label>
              <Input
                id="workspace-name"
                placeholder="Acme Design"
                value={createName}
                onChange={(event) => setCreateName(event.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="workspace-description">Description</Label>
              <Textarea
                id="workspace-description"
                rows={3}
                placeholder="Optional context for members"
                value={createDescription}
                onChange={(event) => setCreateDescription(event.target.value)}
              />
            </div>
          </div>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="ghost" onClick={() => setCreateOpen(false)} type="button">
              Cancel
            </Button>
            <Button onClick={handleCreateWorkspace} disabled={creating || !createName.trim()}>
              {creating ? 'Creating...' : 'Create workspace'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
        <DialogContent className={cn('sm:max-w-md', overlayPanelClass)}>
          <DialogHeader>
            <DialogTitle>Invite a member</DialogTitle>
            <DialogDescription>Enter an email and choose the role for this member.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="invite-email">Email</Label>
              <Input
                id="invite-email"
                type="email"
                placeholder="teammate@example.com"
                value={inviteEmail}
                onChange={(event) => setInviteEmail(event.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={inviteRole} onValueChange={(value) => setInviteRole(value as InviteRoleValue)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a role" />
                </SelectTrigger>
                <SelectContent>
                  {roleOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="ghost" onClick={() => setInviteOpen(false)} type="button">
              Cancel
            </Button>
            <Button onClick={handleSendInvite} disabled={inviting || !inviteEmail.trim()}>
              {inviting ? 'Sending...' : 'Send invitation'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={roleDialogOpen} onOpenChange={setRoleDialogOpen}>
        <DialogContent className={cn('max-h-[90vh] overflow-y-auto sm:max-w-2xl', overlayPanelClass)}>
          <DialogHeader>
            <DialogTitle>{roleDialogMode === 'create' ? 'Create role' : 'Edit role'}</DialogTitle>
            <DialogDescription>Customize permissions for this workspace role.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="role-name">Name</Label>
                <Input
                  id="role-name"
                  placeholder="Design reviewers"
                  value={roleForm.name}
                  onChange={(event) => setRoleForm((prev) => ({ ...prev, name: event.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="role-priority">Priority</Label>
                <Input
                  id="role-priority"
                  type="number"
                  value={roleForm.priority}
                  onChange={(event) =>
                    setRoleForm((prev) => ({ ...prev, priority: Number(event.target.value) || 0 }))
                  }
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="role-description">Description</Label>
              <Textarea
                id="role-description"
                rows={3}
                placeholder="Optional description"
                value={roleForm.description}
                onChange={(event) => setRoleForm((prev) => ({ ...prev, description: event.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <Label>Base role</Label>
              <Select
                value={roleForm.baseRole}
                onValueChange={(value) => setRoleForm((prev) => ({
                  ...prev,
                  baseRole: value as BaseRole,
                  permissions: buildSystemPermissionSet(value as SystemRole),
                }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select base role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="viewer">Viewer</SelectItem>
                  <SelectItem value="editor">Editor</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-4">
              {PERMISSION_GROUPS.map((group) => (
                <div key={group.title} className="rounded-2xl border border-border/50 p-4">
                  <p className="text-sm font-semibold text-foreground">{group.title}</p>
                  <div className="mt-3 space-y-2">
                    {group.permissions.map((permission) => (
                      <div key={permission.id} className="flex items-center justify-between gap-4 rounded-xl bg-muted/40 px-3 py-2">
                        <div>
                          <p className="text-sm font-medium text-foreground">{permission.label}</p>
                        </div>
                        <Switch
                          checked={roleForm.permissions.has(permission.id)}
                          onCheckedChange={(checked) => handlePermissionToggle(permission.id, checked)}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <DialogFooter className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            {roleDialogMode === 'edit' && (
              <Button
                variant="destructive"
                onClick={handleDeleteRole}
                disabled={roleDeleting}
                className="w-full sm:w-auto"
              >
                {roleDeleting ? 'Deleting…' : 'Delete role'}
              </Button>
            )}
            <div className="flex w-full flex-1 justify-end gap-2">
              <Button variant="ghost" onClick={() => setRoleDialogOpen(false)} type="button">
                Cancel
              </Button>
              <Button onClick={handleSubmitRole} disabled={roleSaving}>
                {roleSaving ? 'Saving…' : roleDialogMode === 'create' ? 'Create role' : 'Save changes'}
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
