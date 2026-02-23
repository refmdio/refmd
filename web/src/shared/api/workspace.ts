/**
 * Workspace API
 */

import { api, unwrap } from './core'

export const workspaceApi = {
  async list() {
    return unwrap(await api.GET('/api/workspaces'))
  },

  async create(body: { name: string; description?: string }) {
    return unwrap(await api.POST('/api/workspaces', { body }))
  },

  async update(workspaceId: string, body: { name?: string }) {
    return unwrap(await api.PATCH('/api/workspaces/{workspace_id}', {
      params: { path: { workspace_id: workspaceId } },
      body,
    }))
  },

  async delete(workspaceId: string) {
    return unwrap(await api.DELETE('/api/workspaces/{workspace_id}', {
      params: { path: { workspace_id: workspaceId } },
    }))
  },

  // Members
  async listMembers(workspaceId: string) {
    return unwrap(await api.GET('/api/workspaces/{workspace_id}/members', {
      params: { path: { workspace_id: workspaceId } },
    }))
  },

  async changeMemberRole(workspaceId: string, userId: string, body: { role_id: string }) {
    return unwrap(await api.PATCH('/api/workspaces/{workspace_id}/members/{user_id}', {
      params: { path: { workspace_id: workspaceId, user_id: userId } },
      body,
    }))
  },

  async removeMember(workspaceId: string, userId: string) {
    return unwrap(await api.DELETE('/api/workspaces/{workspace_id}/members/{user_id}', {
      params: { path: { workspace_id: workspaceId, user_id: userId } },
    }))
  },

  // Roles
  async listRoles(workspaceId: string) {
    return unwrap(await api.GET('/api/workspaces/{workspace_id}/roles', {
      params: { path: { workspace_id: workspaceId } },
    }))
  },

  async createRole(workspaceId: string, body: { name: string; base_role: string; is_default?: boolean }) {
    return unwrap(await api.POST('/api/workspaces/{workspace_id}/roles', {
      params: { path: { workspace_id: workspaceId } },
      body,
    }))
  },

  async updateRole(
    workspaceId: string,
    roleId: string,
    body: { name?: string; is_default?: boolean; permission_overrides?: Array<{ permission: string; granted: boolean }> }
  ) {
    return unwrap(await api.PATCH('/api/workspaces/{workspace_id}/roles/{role_id}', {
      params: { path: { workspace_id: workspaceId, role_id: roleId } },
      body,
    }))
  },

  async deleteRole(workspaceId: string, roleId: string) {
    return unwrap(await api.DELETE('/api/workspaces/{workspace_id}/roles/{role_id}', {
      params: { path: { workspace_id: workspaceId, role_id: roleId } },
    }))
  },

  // Invitations
  async listInvitations(workspaceId: string) {
    return unwrap(await api.GET('/api/workspaces/{workspace_id}/invitations', {
      params: { path: { workspace_id: workspaceId } },
    }))
  },

  async createInvitation(
    workspaceId: string,
    body: {
      invitation_id: string
      token_hash: string
      token_prefix: string
      role_id: string | null
      invited_email: string
      encrypted_kek: string
      kek_nonce: string
      kek_version: number
      expires_at: string
    }
  ) {
    return unwrap(await api.POST('/api/workspaces/{workspace_id}/invitations', {
      params: { path: { workspace_id: workspaceId } },
      body,
    }))
  },

  async revokeInvitation(workspaceId: string, invitationId: string) {
    return unwrap(await api.DELETE('/api/workspaces/{workspace_id}/invitations/{invitation_id}', {
      params: { path: { workspace_id: workspaceId, invitation_id: invitationId } },
    }))
  },
}
