import { client, POP_DEVICE_OVERRIDE_HEADER, throwIfError, withUserPopParams } from "./core";
import type { components } from "./schema";

type PopOverrideOptions = {
  popDeviceId?: string;
};

function popOverrideHeaders(options?: PopOverrideOptions): Record<string, string> | undefined {
  return options?.popDeviceId ? { [POP_DEVICE_OVERRIDE_HEADER]: options.popDeviceId } : undefined;
}

export const encryptionApi = {
  getWorkspaceIds: async () => throwIfError(await client.GET("/api/workspaces/ids")),

  appendWorkspaceKeyDirectory: async (
    workspaceId: string,
    body: components["schemas"]["KeyDirectoryAppendRequest"],
    options?: PopOverrideOptions & { ignoreConflict?: boolean },
  ) => {
    const result = await client.POST("/api/workspaces/{workspace_id}/key-directory/append", {
      params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      body,
      headers: popOverrideHeaders(options),
    });

    if (options?.ignoreConflict && result.response.status === 409) return undefined;
    return throwIfError(result);
  },

  getWorkspaceKeysWithPop: async (
    workspaceId: string,
    deviceId: string,
    init?: Pick<RequestInit, "signal">,
  ) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/keys", {
        params: withUserPopParams({
          path: { workspace_id: workspaceId },
          query: { device_id: deviceId },
        }),
        ...init,
      }),
    ),

  createWorkspaceKeyWithPop: async (
    workspaceId: string,
    body: components["schemas"]["CreateWorkspaceKeyRequest"],
    options?: PopOverrideOptions,
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/keys", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
        headers: popOverrideHeaders(options),
      }),
    );
  },

  saveMemberEnvelopes: async (
    workspaceId: string,
    body: components["schemas"]["SaveMemberEnvelopesRequest"],
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/member-envelopes", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    );
  },

  prepareKekRotationCompletion: async (workspaceId: string, newKekVersion: number) =>
    throwIfError(
      await client.GET(
        "/api/encryption/workspaces/{workspace_id}/kek-rotation/completion-manifest",
        {
          params: withUserPopParams({
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
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    );
  },

  startKekRotation: async (
    workspaceId: string,
    body: components["schemas"]["KekRotationStartRequest"],
  ) => {
    return throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-rotation", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body,
      }),
    );
  },

  getMemberEnvelopeWithPop: async (workspaceId: string) => {
    const result = await client.GET("/api/encryption/workspaces/{workspace_id}/member-envelope", {
      params: withUserPopParams({ path: { workspace_id: workspaceId } }),
    });
    if (result.response.status === 404) return null;
    return throwIfError(result);
  },

  getWorkspaceMemberKeys: async (workspaceId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/member-keys", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        ...init,
      }),
    ),

  setupComplete: async () => throwIfError(await client.POST("/api/encryption/setup-complete")),

  getDocumentKeys: async (documentId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/encryption/documents/{document_id}/keys", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        ...init,
      }),
    ),

  createDocumentKey: async (
    documentId: string,
    body: components["schemas"]["CreateDocumentKeyRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/encryption/documents/{document_id}/keys", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),
};
