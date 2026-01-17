import { getWorkspaceKeyVersion } from '@/shared/api/client'

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
  updateInvitationKek,
  type PermissionOverridePayload,
} from '@/entities/workspace/api'

import { getKeyVaultService } from '@/features/security'

import type { SystemRole } from './permissions'

export type WorkspaceRoleSelection =
  | { kind: 'system'; systemRole: SystemRole }
  | { kind: 'custom'; customRoleId: string }

export async function createWorkspaceAction(params: { name: string; description?: string; icon?: string }) {
  // 1. Create workspace
  const workspace = await createWorkspace({
    name: params.name.trim(),
    description: params.description?.trim() || undefined,
    icon: params.icon,
  })

  // 2. Create KEK if KeyVault is unlocked
  const service = getKeyVaultService()
  await service.ready()
  console.log('[workspace] Creating KEK for workspace:', workspace.id, 'isUnlocked:', service.isUnlocked)
  if (service.isUnlocked) {
    try {
      await service.keyManager.createAndStoreWorkspaceKek(workspace.id)
      console.log('[workspace] KEK created successfully for workspace:', workspace.id)
    } catch (error) {
      console.error('[workspace] Failed to create KEK:', error)
      // Don't throw - workspace is created, KEK can be created later
    }
  } else {
    console.warn('[workspace] KeyVault is not unlocked, skipping KEK creation')
  }

  return workspace
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
  const service = getKeyVaultService()
  await service.ready()

  // 1. Build role payload
  const payload =
    params.selection.kind === 'custom'
      ? { role_kind: 'custom' as const, custom_role_id: params.selection.customRoleId }
      : { role_kind: 'system' as const, system_role: params.selection.systemRole }

  // 2. Create invitation (token returned)
  const invitation = await createWorkspaceInvitation(params.workspaceId, {
    email: params.email.trim(),
    ...payload,
  })

  // 3. If KeyVault unlocked, encrypt KEK for invitation
  if (service.isUnlocked && invitation.token) {
    try {
      // Get current key version
      const versionResponse = await getWorkspaceKeyVersion({ id: params.workspaceId })
      const kekVersion = versionResponse.keyVersion ?? 1

      // Encrypt KEK with invitation token
      const encryptedKekForInvite = await service.keyManager.encryptKekForInvitationToken(
        params.workspaceId,
        invitation.token
      )

      // Update invitation with encrypted KEK
      await updateInvitationKek(params.workspaceId, invitation.id, {
        encryptedKekForInvite,
        kekVersion,
      })
    } catch (error) {
      console.error('[workspace] Failed to encrypt KEK for invitation:', error)
      // Don't throw - invitation is created, but KEK sharing will need manual handling
    }
  }

  return invitation
}

export async function revokeWorkspaceInvitationAction(workspaceId: string, invitationId: string) {
  return revokeWorkspaceInvitation(workspaceId, invitationId)
}

export async function acceptWorkspaceInvitationAction(token: string) {
  // 1. Accept invitation
  const response = await acceptWorkspaceInvitation(token)

  // 2. If encrypted KEK provided, decrypt and store
  const service = getKeyVaultService()
  await service.ready()
  if (
    service.isUnlocked &&
    response.encryptedKekForInvite &&
    response.kekVersion
  ) {
    try {
      await service.keyManager.acceptInvitationAndStoreKek(
        response.workspaceId,
        token,
        response.encryptedKekForInvite,
        response.kekVersion
      )
    } catch (error) {
      console.error('[workspace] Failed to decrypt and store KEK from invitation:', error)
      // Don't throw - invitation is accepted, but KEK will need to be shared manually
    }
  }

  return response
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
