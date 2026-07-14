import { client, RRP_DEVICE_OVERRIDE_HEADER, throwIfError, withUserRrpParams } from "./core";
import type { components } from "./schema";

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

  appendWorkspaceKeyDirectory: async (
    workspaceId: string,
    body: components["schemas"]["KeyDirectoryAppendRequest"],
    options?: RrpOverrideOptions & { ignoreConflict?: boolean },
  ) => {
    const result = await client.POST("/api/workspaces/{workspace_id}/key-directory/append", {
      params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
      body,
      headers: rrpOverrideHeaders(options),
    });

    if (options?.ignoreConflict && result.response.status === 409) return undefined;
    return throwIfError(result);
  },

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

  prepareKekRotationCompletion: async (workspaceId: string, newKekVersion: number) =>
    throwIfError(
      await client.GET(
        "/api/encryption/workspaces/{workspace_id}/kek-rotation/completion-manifest",
        {
          params: withUserRrpParams({
            path: { workspace_id: workspaceId },
            query: { new_kek_version: newKekVersion },
          }),
        },
      ),
    ),

  completeKekRotation: async (
    workspaceId: string,
    body: components["schemas"]["KekRotationCompleteRequest"],
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-rotation/complete", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    );
  },

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

  startKekRotation: async (
    workspaceId: string,
    body: components["schemas"]["KekRotationStartRequest"],
  ) => {
    return throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-rotation", {
        params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    );
  },

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
