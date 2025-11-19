import {
  acceptWorkspaceInvitation,
  createWorkspace,
  createWorkspaceInvitation,
  createWorkspaceRole,
  deleteWorkspace,
  deleteWorkspaceRole,
  leaveWorkspace,
  removeWorkspaceMember,
  revokeWorkspaceInvitation,
  updateWorkspace,
  updateWorkspaceMemberRole,
  updateWorkspaceRole,
  type PermissionOverridePayload,
} from '@/entities/workspace/api'

import type { SystemRole } from './permissions'

export type WorkspaceRoleSelection =
  | { kind: 'system'; systemRole: SystemRole }
  | { kind: 'custom'; customRoleId: string }

export async function createWorkspaceAction(params: { name: string; description?: string; icon?: string }) {
  return createWorkspace({
    name: params.name.trim(),
    description: params.description?.trim() || undefined,
    icon: params.icon,
  })
}

export async function updateWorkspaceSettingsAction(params: {
  workspaceId: string
  name: string
  description?: string
  icon?: string
}) {
  return updateWorkspace(params.workspaceId, {
    name: params.name.trim(),
    description: params.description?.trim() ?? undefined,
    icon: params.icon,
  })
}

export async function deleteWorkspaceAction(workspaceId: string) {
  return deleteWorkspace(workspaceId)
}

export async function leaveWorkspaceAction(workspaceId: string) {
  return leaveWorkspace(workspaceId)
}

export async function sendWorkspaceInvitationAction(params: {
  workspaceId: string
  email: string
  selection: WorkspaceRoleSelection
}) {
  const payload =
    params.selection.kind === 'custom'
      ? { role_kind: 'custom' as const, custom_role_id: params.selection.customRoleId }
      : { role_kind: 'system' as const, system_role: params.selection.systemRole }
  return createWorkspaceInvitation(params.workspaceId, {
    email: params.email.trim(),
    ...payload,
  })
}

export async function revokeWorkspaceInvitationAction(workspaceId: string, invitationId: string) {
  return revokeWorkspaceInvitation(workspaceId, invitationId)
}

export async function acceptWorkspaceInvitationAction(token: string) {
  return acceptWorkspaceInvitation(token)
}

export async function updateWorkspaceMemberRoleAction(params: {
  workspaceId: string
  memberId: string
  selection: WorkspaceRoleSelection
}) {
  const payload =
    params.selection.kind === 'custom'
      ? { role_kind: 'custom' as const, custom_role_id: params.selection.customRoleId }
      : { role_kind: 'system' as const, system_role: params.selection.systemRole }
  return updateWorkspaceMemberRole(params.workspaceId, params.memberId, payload)
}

export async function removeWorkspaceMemberAction(workspaceId: string, memberId: string) {
  return removeWorkspaceMember(workspaceId, memberId)
}

export async function createWorkspaceRoleAction(params: {
  workspaceId: string
  name: string
  baseRole: string
  description?: string
  priority: number
  overrides: PermissionOverridePayload[]
}) {
  return createWorkspaceRole(params.workspaceId, {
    name: params.name.trim(),
    base_role: params.baseRole,
    description: params.description?.trim() || undefined,
    priority: params.priority,
    overrides: params.overrides,
  })
}

export async function updateWorkspaceRoleAction(params: {
  workspaceId: string
  roleId: string
  name: string
  baseRole: string
  description?: string
  priority: number
  overrides: PermissionOverridePayload[]
}) {
  return updateWorkspaceRole(params.workspaceId, params.roleId, {
    name: params.name.trim(),
    base_role: params.baseRole,
    description: params.description?.trim() || undefined,
    priority: params.priority,
    overrides: params.overrides,
  })
}

export async function deleteWorkspaceRoleAction(workspaceId: string, roleId: string) {
  return deleteWorkspaceRole(workspaceId, roleId)
}
