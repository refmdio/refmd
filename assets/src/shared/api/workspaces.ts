import { client, throwIfError } from "./core";

export const workspacesApi = {
  list: async () => throwIfError(await client.GET("/api/workspaces")),

  get: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  create: async (body: { name: string; description?: string | null; icon?: string | null }) =>
    throwIfError(
      await client.POST("/api/workspaces", {
        body,
      }),
    ),

  update: async (
    workspaceId: string,
    body: { name?: string; slug?: string; description?: string | null; icon?: string | null },
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}", {
        params: { path: { workspace_id: workspaceId } },
        body,
      }),
    ),

  delete: async (workspaceId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  // Members
  listMembers: async (workspaceId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/members", {
        params: { path: { workspace_id: workspaceId } },
        ...init,
      }),
    ),

  changeMemberRole: async (workspaceId: string, userId: string, roleId: string) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/members/{user_id}", {
        params: { path: { workspace_id: workspaceId, user_id: userId } },
        body: { role_id: roleId },
      }),
    ),

  removeMember: async (workspaceId: string, userId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/members/{user_id}", {
        params: { path: { workspace_id: workspaceId, user_id: userId } },
      }),
    ),

  // Roles
  listRoles: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/roles", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  createRole: async (
    workspaceId: string,
    body: {
      name: string;
      base_role: "admin" | "editor" | "viewer";
      permissions?: Array<{ permission: string; granted: boolean }>;
    },
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/roles", {
        params: { path: { workspace_id: workspaceId } },
        body,
      }),
    ),

  updateRole: async (
    workspaceId: string,
    roleId: string,
    body: {
      name?: string;
      is_default?: boolean;
      permissions?: Array<{ permission: string; granted: boolean }>;
    },
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/roles/{role_id}", {
        params: { path: { workspace_id: workspaceId, role_id: roleId } },
        body,
      }),
    ),

  deleteRole: async (workspaceId: string, roleId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/roles/{role_id}", {
        params: { path: { workspace_id: workspaceId, role_id: roleId } },
      }),
    ),

  // Invitations
  listInvitations: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/invitations", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  createInvitation: async (
    workspaceId: string,
    body: {
      invitation_id: string;
      token_hash: string;
      token_prefix: string;
      encrypted_kek: string;
      kek_nonce: string;
      kek_version: number;
      role_id?: string | null;
      invited_email: string;
      expires_at?: string;
    },
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/invitations", {
        params: { path: { workspace_id: workspaceId } },
        body,
      }),
    ),

  revokeInvitation: async (workspaceId: string, invitationId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/invitations/{invitation_id}", {
        params: {
          path: { workspace_id: workspaceId, invitation_id: invitationId },
        },
      }),
    ),

  listMemberDevices: async (
    workspaceId: string,
    userId: string,
    includeRevoked = false,
    init?: Pick<RequestInit, "signal">,
  ) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/members/{user_id}/devices", {
        params: {
          path: { workspace_id: workspaceId, user_id: userId },
          query: includeRevoked ? { include_revoked: true } : {},
        },
        ...init,
      }),
    ),

  acceptInvitation: async (token: string) =>
    throwIfError(
      await client.POST("/api/workspaces/invitations/accept", {
        body: { token },
      }),
    ),
};
