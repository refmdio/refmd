import { client, throwIfError, withUserRrpParams } from "./core";
import type { components } from "./schema";
import type { GenesisCompoundAuthorization } from "@/shared/lib/crypto/genesis-authorization";

type InvitationRecipientResponse = components["schemas"]["InvitationRecipientResponse"];

export const workspacesApi = {
  list: async () =>
    throwIfError(await client.GET("/api/workspaces", { params: withUserRrpParams() })),

  get: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  createIntent: async (body: components["schemas"]["WorkspaceGenesisCommand"]) =>
    throwIfError(
      await client.POST("/api/workspaces/intent", {
        params: withUserRrpParams(),
        body: body as never,
      }),
    ),

  create: async (body: components["schemas"]["WorkspaceGenesisAuthorization"]) =>
    throwIfError(
      await client.POST("/api/workspaces", {
        body: body as never,
      }),
    ),

  update: async (workspaceId: string, body: components["schemas"]["UpdateWorkspaceRequest"]) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  updateFeatures: async (
    workspaceId: string,
    body: components["schemas"]["UpdateWorkspaceFeaturesRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/features", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  delete: async (workspaceId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  // Members
  listMembers: async (workspaceId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/members", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        ...init,
      }),
    ),

  prepareMemberRoleChange: async (
    workspaceId: string,
    userId: string,
    body: components["schemas"]["MemberRoleIntentRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/members/{user_id}/role/intent", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId, user_id: userId } }),
        body,
      }),
    ),

  prepareMemberRemoval: async (
    workspaceId: string,
    userId: string,
    body: components["schemas"]["MemberRemovalIntentRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/members/{user_id}/removal/intent", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId, user_id: userId } }),
        body,
      }),
    ),

  commitMemberRoleChange: async (
    workspaceId: string,
    userId: string,
    body: GenesisCompoundAuthorization,
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/members/{user_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId, user_id: userId } }),
        body: body as never,
      }),
    ),

  commitMemberRemoval: async (
    workspaceId: string,
    userId: string,
    body: GenesisCompoundAuthorization,
  ) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/members/{user_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId, user_id: userId } }),
        body: body as never,
      }),
    ),

  // Roles
  listRoles: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/roles", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
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
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
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
      workspace_key_directory_events?: components["schemas"]["KeyDirectoryEnvelope"][];
      workspace_key_directory_checkpoint?: components["schemas"]["KeyDirectoryEnvelope"];
    },
  ) =>
    throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/roles/{role_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId, role_id: roleId } }),
        body,
      }),
    ),

  deleteRole: async (workspaceId: string, roleId: string) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/roles/{role_id}", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId, role_id: roleId } }),
      }),
    ),

  // Invitations
  listInvitations: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/invitations", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  createInvitation: async (
    workspaceId: string,
    body: components["schemas"]["CreateInvitationRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/invitations", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  resolveInvitationRecipient: async (
    workspaceId: string,
    email: string,
  ): Promise<InvitationRecipientResponse> =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/invitations/recipient", {
        params: withUserRrpParams({
          path: { workspace_id: workspaceId },
          query: { email },
        }),
      }),
    ) as InvitationRecipientResponse,

  revokeInvitation: async (
    workspaceId: string,
    invitationId: string,
    body: components["schemas"]["RevokeInvitationRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/invitations/{invitation_id}", {
        params: withUserRrpParams({
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
        params: withUserRrpParams({
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
        params: withUserRrpParams(),
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
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
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
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    ),

  resolveGuestInvitationRecipient: async (
    workspaceId: string,
    email: string,
  ): Promise<InvitationRecipientResponse> =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/guest-invitations/recipient", {
        params: withUserRrpParams({
          path: { workspace_id: workspaceId },
          query: { email },
        }),
      }),
    ) as InvitationRecipientResponse,

  revokeGuestInvitation: async (
    workspaceId: string,
    invitationId: string,
    body: components["schemas"]["RevokeInvitationRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/guest-invitations/{invitation_id}", {
        params: withUserRrpParams({
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

  redeemKnownGuestInvitation: async (body: components["schemas"]["RedeemGuestInvitationRequest"]) =>
    throwIfError(
      await client.POST("/api/guest/redeem-known", {
        params: withUserRrpParams(),
        body,
      }),
    ),

  createInvitationDeliveryAttempt: async (
    body: components["schemas"]["CreateInvitationDeliveryAttemptRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/invitations/delivery-attempts", {
        params: withUserRrpParams(),
        body,
      }),
    ),

  getInvitationDeliveryAttempt: async (attemptId: string) =>
    throwIfError(
      await client.GET("/api/invitations/delivery-attempts/{attempt_id}", {
        params: withUserRrpParams({ path: { attempt_id: attemptId } }),
      }),
    ),

  listInvitationDeliveryAttempts: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/invitation-delivery-attempts", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
      }),
    ),

  approveInvitationDeliveryAttempt: async (
    workspaceId: string,
    attemptId: string,
    body: components["schemas"]["ApproveInvitationDeliveryAttemptRequest"],
  ) =>
    throwIfError(
      await client.POST(
        "/api/workspaces/{workspace_id}/invitation-delivery-attempts/{attempt_id}/approve",
        {
          params: withUserRrpParams({
            path: { workspace_id: workspaceId, attempt_id: attemptId },
          }),
          body,
        },
      ),
    ),

  consumeWorkspaceInvitationDeliveryAttempt: async (
    attemptId: string,
    body: components["schemas"]["ConsumeInvitationDeliveryAttemptRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/workspaces/invitations/delivery-attempts/{attempt_id}/consume", {
        params: withUserRrpParams({ path: { attempt_id: attemptId } }),
        body,
      }),
    ),

  consumeGuestInvitationDeliveryAttempt: async (
    attemptId: string,
    body: components["schemas"]["ConsumeInvitationDeliveryAttemptRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/guest/invitations/delivery-attempts/{attempt_id}/consume", {
        params: withUserRrpParams({ path: { attempt_id: attemptId } }),
        body,
      }),
    ),
};
