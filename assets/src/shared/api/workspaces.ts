import { client, throwIfError, withUserPopParams } from "./core";
import type { components } from "./schema";

export const workspacesApi = {
  list: async () =>
    throwIfError(await client.GET("/api/workspaces", { params: withUserPopParams() })),

  get: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  create: async (body: components["schemas"]["CreateWorkspaceRequest"]) =>
    throwIfError(
      await client.POST("/api/workspaces", {
        body,
      }),
    ),

  update: async (workspaceId: string, body: components["schemas"]["UpdateWorkspaceRequest"]) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  updateFeatures: async (
    workspaceId: string,
    body: components["schemas"]["UpdateWorkspaceFeaturesRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/features", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  delete: async (workspaceId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  // Members
  listMembers: async (workspaceId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/members", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        ...init,
      }),
    ),

  changeMemberRole: async (
    workspaceId: string,
    userId: string,
    body: components["schemas"]["ChangeMemberRoleRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/members/{user_id}", {
        params: withUserPopParams({ path: { workspace_id: workspaceId, user_id: userId } }),
        body,
      }),
    ),

  removeMember: async (
    workspaceId: string,
    userId: string,
    body: components["schemas"]["RemoveMemberRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/members/{user_id}", {
        params: withUserPopParams({ path: { workspace_id: workspaceId, user_id: userId } }),
        body,
      }),
    ),

  // Roles
  listRoles: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/roles", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
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
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
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
        params: withUserPopParams({ path: { workspace_id: workspaceId, role_id: roleId } }),
        body,
      }),
    ),

  deleteRole: async (workspaceId: string, roleId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/roles/{role_id}", {
        params: withUserPopParams({ path: { workspace_id: workspaceId, role_id: roleId } }),
      }),
    ),

  // Invitations
  listInvitations: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/invitations", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  createInvitation: async (
    workspaceId: string,
    body: components["schemas"]["CreateInvitationRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/invitations", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  revokeInvitation: async (
    workspaceId: string,
    invitationId: string,
    body: components["schemas"]["RevokeInvitationRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/invitations/{invitation_id}", {
        params: withUserPopParams({
          path: { workspace_id: workspaceId, invitation_id: invitationId },
        }),
        body,
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
        params: withUserPopParams({
          path: { workspace_id: workspaceId, user_id: userId },
          query: includeRevoked ? { include_revoked: true } : {},
        }),
        ...init,
      }),
    ),

  acceptInvitation: async (
    token: string,
    body: Omit<components["schemas"]["AcceptInvitationRequest"], "token">,
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/invitations/accept", {
        params: withUserPopParams(),
        body: { token, ...body },
      }),
    ),

  lookupInvitation: async (token: string) =>
    throwIfError(
      await client.GET("/api/invitations/lookup", {
        params: { query: { token } },
      }),
    ),

  // Guest invitations
  listGuestInvitations: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/guest-invitations", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  createGuestInvitation: async (
    workspaceId: string,
    body: components["schemas"]["CreateGuestInvitationRequest"] & {
      encrypted_bootstrap_package: Record<string, unknown>;
      bootstrap_key_commitment: string;
    },
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/guest-invitations", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  revokeGuestInvitation: async (
    workspaceId: string,
    invitationId: string,
    body: components["schemas"]["RevokeInvitationRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/guest-invitations/{invitation_id}", {
        params: withUserPopParams({
          path: { workspace_id: workspaceId, invitation_id: invitationId },
        }),
        body,
      }),
    ),

  redeemGuestInvitation: async (body: components["schemas"]["RedeemGuestInvitationRequest"]) =>
    throwIfError(
      await client.POST("/api/guest/redeem", {
        body,
      }),
    ),
};
