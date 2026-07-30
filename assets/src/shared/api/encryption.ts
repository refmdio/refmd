import { client, RRP_DEVICE_OVERRIDE_HEADER, throwIfError, withUserRrpParams } from "./core";
import type { components } from "./schema";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { GenesisCompoundAuthorization } from "@/shared/lib/crypto/genesis-authorization";

type RrpOverrideOptions = {
  rrpDeviceId?: string;
};

function rrpOverrideHeaders(options?: RrpOverrideOptions): Record<string, string> | undefined {
  return options?.rrpDeviceId ? { [RRP_DEVICE_OVERRIDE_HEADER]: options.rrpDeviceId } : undefined;
}

export const encryptionApi = {
  getWorkspaceIds: async (options?: RrpOverrideOptions) =>
    throwIfError(
      await client.GET("/api/workspaces/ids", {
        headers: rrpOverrideHeaders(options),
      }),
    ),

  getIdentityRotationStatus: async (options?: RrpOverrideOptions) =>
    throwIfError(
      await client.GET("/api/encryption/identity-rotation", {
        params: withUserRrpParams({}),
        headers: rrpOverrideHeaders(options),
      }),
    ),

  prepareIdentityRotation: async (
    body: components["schemas"]["IdentityRotationPrepareRequest"],
    options?: RrpOverrideOptions,
  ) =>
    throwIfError(
      await client.POST("/api/encryption/identity-rotation/prepare", {
        params: withUserRrpParams({}),
        headers: rrpOverrideHeaders(options),
        body,
      }),
    ),

  activateIdentityRotation: async (
    body: components["schemas"]["IdentityRotationActivateRequest"],
    options?: RrpOverrideOptions,
  ) =>
    throwIfError(
      await client.POST("/api/encryption/identity-rotation/activate", {
        params: withUserRrpParams({}),
        headers: rrpOverrideHeaders(options),
        body,
      }),
    ),

  finalizeIdentityRotation: async (
    body: components["schemas"]["IdentityRotationFinalizeRequest"],
    options?: RrpOverrideOptions,
  ) =>
    throwIfError(
      await client.POST("/api/encryption/identity-rotation/finalize", {
        params: withUserRrpParams({}),
        headers: rrpOverrideHeaders(options),
        body,
      }),
    ),

  getWorkspaceKeysWithRrp: async (
    workspaceId: string,
    deviceId: string,
    options?: RrpOverrideOptions & Pick<RequestInit, "signal">,
  ) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/keys", {
        params: withUserRrpParams({
          path: { workspace_id: workspaceId },
          query: { device_id: deviceId },
        }),
        headers: rrpOverrideHeaders(options),
        ...(options?.signal ? { signal: options.signal } : {}),
      }),
    ),

  createWorkspaceKeyWithRrp: async (
    workspaceId: string,
    body: components["schemas"]["CreateWorkspaceKeyRequest"],
    options?: RrpOverrideOptions,
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/keys", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
        headers: rrpOverrideHeaders(options),
      }),
    );
  },

  saveMemberEnvelopes: async (
    workspaceId: string,
    body: components["schemas"]["SaveMemberEnvelopesRequest"],
    options?: RrpOverrideOptions,
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/member-envelopes", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
        headers: rrpOverrideHeaders(options),
      }),
    );
  },

  prepareKekRotationCompletion: async (
    workspaceId: string,
    rotationId: string,
    body: StrictJsonValue,
  ) =>
    throwIfError(
      await client.POST(
        "/api/encryption/workspaces/{workspace_id}/rotations/{rotation_id}/complete/intent",
        {
          params: withUserRrpParams({
            path: { workspace_id: workspaceId, rotation_id: rotationId },
          }),
          body: body as never,
        },
      ),
    ),

  completeKekRotation: async (
    workspaceId: string,
    rotationId: string,
    body: GenesisCompoundAuthorization,
  ) => {
    return throwIfError(
      await client.POST(
        "/api/encryption/workspaces/{workspace_id}/rotations/{rotation_id}/complete",
        {
          params: withUserRrpParams({
            path: { workspace_id: workspaceId, rotation_id: rotationId },
          }),
          body: body as never,
        },
      ),
    );
  },

  prepareOldKekDeletion: async (workspaceId: string, rotationId: string, body: StrictJsonValue) =>
    throwIfError(
      await client.POST(
        "/api/encryption/workspaces/{workspace_id}/rotations/{rotation_id}/old-key-deletion/intent",
        {
          params: withUserRrpParams({
            path: { workspace_id: workspaceId, rotation_id: rotationId },
          }),
          body: body as never,
        },
      ),
    ),

  deleteOldKek: async (
    workspaceId: string,
    rotationId: string,
    body: GenesisCompoundAuthorization,
  ) =>
    throwIfError(
      await client.POST(
        "/api/encryption/workspaces/{workspace_id}/rotations/{rotation_id}/old-key-deletion",
        {
          params: withUserRrpParams({
            path: { workspace_id: workspaceId, rotation_id: rotationId },
          }),
          body: body as never,
        },
      ),
    ),

  getWorkspaceWipeRequirement: async (workspaceId: string) => {
    const result = await client.GET(
      "/api/encryption/workspaces/{workspace_id}/kek-rotation/wipe-requirement",
      { params: withUserRrpParams({ path: { workspace_id: workspaceId } }) },
    );
    if (result.response.status === 404) return null;
    return throwIfError(result);
  },

  acknowledgeWorkspaceWipe: async (
    workspaceId: string,
    body: components["schemas"]["WorkspaceWipeAcknowledgementRequest"],
  ) =>
    throwIfError(
      await client.POST(
        "/api/encryption/workspaces/{workspace_id}/kek-rotation/wipe-requirement/acknowledge",
        {
          params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
          body,
        },
      ),
    ),

  prepareKekRotationStart: async (
    workspaceId: string,
    body: components["schemas"]["KekRotationStartIntentRequest"],
  ) => {
    return throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-rotation/intent", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    );
  },

  commitKekRotationStart: async (workspaceId: string, body: GenesisCompoundAuthorization) =>
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-rotation", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body: body as never,
      }),
    ),

  getMemberEnvelopeWithRrp: async (workspaceId: string, options?: RrpOverrideOptions) => {
    const result = await client.GET("/api/encryption/workspaces/{workspace_id}/member-envelope", {
      params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
      headers: rrpOverrideHeaders(options),
    });
    if (result.response.status === 404) return null;
    return throwIfError(result);
  },

  getWorkspaceMemberKeys: async (workspaceId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/member-keys", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        ...init,
      }),
    ),

  setupComplete: async () => throwIfError(await client.POST("/api/encryption/setup-complete")),

  getDocumentKeys: async (documentId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/encryption/documents/{document_id}/keys", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
        ...init,
      }),
    ),

  getDocumentKeyRotationTargets: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/encryption/documents/{document_id}/keys/rotation-targets", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
      }),
    ),

  prepareDekRotationCompletion: async (documentId: string, newKeyVersion: number) =>
    throwIfError(
      await client.GET("/api/encryption/documents/{document_id}/keys/rotation-completion", {
        params: withUserRrpParams({
          path: { document_id: documentId },
          query: { new_key_version: newKeyVersion },
        }),
      }),
    ),

  completeDekRotation: async (
    documentId: string,
    body: components["schemas"]["DekRotationCompletionRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/encryption/documents/{document_id}/keys/rotation-completion", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  getDocumentWipeRequirement: async (documentId: string) => {
    const result = await client.GET(
      "/api/encryption/documents/{document_id}/keys/wipe-requirement",
      {
        params: withUserRrpParams({ path: { document_id: documentId } }),
      },
    );
    if (result.response.status === 404) return null;
    return throwIfError(result);
  },

  acknowledgeDocumentWipe: async (
    documentId: string,
    body: components["schemas"]["DocumentWipeAcknowledgementRequest"],
  ) =>
    throwIfError(
      await client.POST(
        "/api/encryption/documents/{document_id}/keys/wipe-requirement/acknowledge",
        {
          params: withUserRrpParams({ path: { document_id: documentId } }),
          body,
        },
      ),
    ),

  createDocumentKey: async (
    documentId: string,
    body: components["schemas"]["CreateDocumentKeyRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/encryption/documents/{document_id}/keys", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  rewrapDocumentKeyForKekRotation: async (
    documentId: string,
    body: components["schemas"]["RewrapDocumentKeyForKekRotationRequest"],
  ) =>
    throwIfError(
      await client.PUT("/api/encryption/documents/{document_id}/keys/kek-rotation-rewrap", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
        body,
      }),
    ),
};
