import {
  acceptInvitation as apiAcceptWorkspaceInvitation,
  createInvitation as apiCreateWorkspaceInvitation,
  createRole as apiCreateWorkspaceRole,
  createWorkspace as apiCreateWorkspace,
  deleteRole as apiDeleteWorkspaceRole,
  deleteWorkspace as apiDeleteWorkspace,
  getWorkspaceDetail as apiGetWorkspaceDetail,
  leaveWorkspace as apiLeaveWorkspace,
  listInvitations as apiListWorkspaceInvitations,
  listMembers as apiListWorkspaceMembers,
  listRoles as apiListWorkspaceRoles,
  removeMember as apiRemoveWorkspaceMember,
  revokeInvitation as apiRevokeWorkspaceInvitation,
  updateInvitationKek as apiUpdateInvitationKek,
  updateMemberRole as apiUpdateWorkspaceMemberRole,
  updateRole as apiUpdateWorkspaceRole,
  updateWorkspace as apiUpdateWorkspace,
} from '@/shared/api'
import type {
  PermissionOverridePayload as ApiPermissionOverridePayload,
  WorkspaceInvitationResponse as ApiWorkspaceInvitationResponse,
  WorkspaceMemberResponse as ApiWorkspaceMemberResponse,
  WorkspaceResponse,
  WorkspaceRoleResponse as ApiWorkspaceRoleResponse,
} from '@/shared/api'

export const workspaceKeys = {
  members: (workspaceId?: string | null) => ['workspace-members', workspaceId] as const,
  roles: (workspaceId?: string | null) => ['workspace-roles', workspaceId] as const,
  invitations: (workspaceId?: string | null) => ['workspace-invitations', workspaceId] as const,
}

export type UpdateWorkspacePayload = {
  name?: string
  icon?: string
  description?: string
}

export type CreateWorkspacePayload = {
  name: string
  description?: string
  icon?: string
}

export type PermissionOverridePayload = ApiPermissionOverridePayload
export type WorkspaceInvitationResponse = ApiWorkspaceInvitationResponse
export type WorkspaceMemberResponse = ApiWorkspaceMemberResponse
export type WorkspaceRoleResponse = ApiWorkspaceRoleResponse

export function getWorkspace(id: string): Promise<WorkspaceResponse> {
  return apiGetWorkspaceDetail({ id }) as Promise<WorkspaceResponse>
}

export function updateWorkspace(id: string, body: UpdateWorkspacePayload): Promise<WorkspaceResponse> {
  return apiUpdateWorkspace({ id, requestBody: body }) as Promise<WorkspaceResponse>
}

export function deleteWorkspace(id: string): Promise<void> {
  return apiDeleteWorkspace({ id }) as Promise<void>
}

export function leaveWorkspace(id: string): Promise<void> {
  return apiLeaveWorkspace({ id }) as Promise<void>
}

export function createWorkspace(body: CreateWorkspacePayload) {
  return apiCreateWorkspace({ requestBody: body })
}

export function listWorkspaceMembers(workspaceId: string) {
  return apiListWorkspaceMembers({ id: workspaceId }) as Promise<WorkspaceMemberResponse[]>
}

export function listWorkspaceRoles(workspaceId: string) {
  return apiListWorkspaceRoles({ id: workspaceId }) as Promise<WorkspaceRoleResponse[]>
}

export function listWorkspaceInvitations(workspaceId: string) {
  return apiListWorkspaceInvitations({ id: workspaceId }) as Promise<WorkspaceInvitationResponse[]>
}

export function createWorkspaceInvitation(
  workspaceId: string,
  payload: {
    email: string
    role_kind: 'system' | 'custom'
    system_role?: string
    custom_role_id?: string
  },
) {
  return apiCreateWorkspaceInvitation({
    id: workspaceId,
    requestBody: payload,
  })
}

export function revokeWorkspaceInvitation(workspaceId: string, invitationId: string) {
  return apiRevokeWorkspaceInvitation({ id: workspaceId, invitationId })
}

export function acceptWorkspaceInvitation(token: string) {
  return apiAcceptWorkspaceInvitation({ token })
}

export function updateWorkspaceMemberRole(
  workspaceId: string,
  userId: string,
  payload: {
    role_kind: 'system' | 'custom'
    system_role?: string
    custom_role_id?: string
  },
) {
  return apiUpdateWorkspaceMemberRole({ id: workspaceId, userId, requestBody: payload })
}

export function removeWorkspaceMember(workspaceId: string, userId: string) {
  return apiRemoveWorkspaceMember({ id: workspaceId, userId })
}

export function createWorkspaceRole(
  workspaceId: string,
  payload: {
    name: string
    base_role: string
    description?: string
    priority?: number
    overrides?: PermissionOverridePayload[]
  },
) {
  return apiCreateWorkspaceRole({ id: workspaceId, requestBody: payload })
}

export function updateWorkspaceRole(
  workspaceId: string,
  roleId: string,
  payload: {
    name?: string
    base_role?: string
    description?: string
    priority?: number
    overrides?: PermissionOverridePayload[]
  },
) {
  return apiUpdateWorkspaceRole({ id: workspaceId, roleId, requestBody: payload })
}

export function deleteWorkspaceRole(workspaceId: string, roleId: string) {
  return apiDeleteWorkspaceRole({ id: workspaceId, roleId })
}

/**
 * Update invitation with encrypted KEK.
 * Called after creating an invitation to attach the encrypted workspace KEK.
 *
 * @param workspaceId - Workspace ID
 * @param invitationId - Invitation ID
 * @param payload - Encrypted KEK data
 */
export async function updateInvitationKek(
  workspaceId: string,
  invitationId: string,
  payload: {
    encryptedKekForInvite: string
    kekVersion: number
  }
): Promise<void> {
  await apiUpdateInvitationKek({
    id: workspaceId,
    invitationId,
    requestBody: payload,
  })
}
