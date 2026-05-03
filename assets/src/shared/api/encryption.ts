import { client, POP_DEVICE_OVERRIDE_HEADER, throwIfError } from "./core";
import type { components } from "./schema";

type PopOverrideOptions = {
  popDeviceId?: string;
};

function popOverrideHeaders(options?: PopOverrideOptions): Record<string, string> | undefined {
  return options?.popDeviceId ? { [POP_DEVICE_OVERRIDE_HEADER]: options.popDeviceId } : undefined;
}

export const encryptionApi = {
  getWorkspaceIds: async () => throwIfError(await client.GET("/api/workspaces/ids")),

  getWorkspaceKeysWithPop: async (
    workspaceId: string,
    deviceId: string,
    init?: Pick<RequestInit, "signal">,
  ) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/keys", {
        params: {
          path: { workspace_id: workspaceId },
          query: { device_id: deviceId },
        },
        ...init,
      }),
    ),

  getKekBackupWithPop: async (workspaceId: string, keyVersion?: number) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/kek-backup", {
        params: {
          path: { workspace_id: workspaceId },
          ...(keyVersion !== undefined ? { query: { key_version: keyVersion } } : {}),
        },
      }),
    ),

  createWorkspaceKeyWithPop: async (
    workspaceId: string,
    body: components["schemas"]["CreateWorkspaceKeyRequest"],
    options?: PopOverrideOptions,
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/keys", {
        params: { path: { workspace_id: workspaceId } },
        body,
        headers: popOverrideHeaders(options),
      }),
    );
  },

  createKekBackupWithPop: async (
    workspaceId: string,
    body: components["schemas"]["CreateKekBackupRequest"],
    options?: PopOverrideOptions,
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-backup", {
        params: { path: { workspace_id: workspaceId } },
        body,
        headers: popOverrideHeaders(options),
      }),
    );
  },

  saveMemberEnvelopes: async (
    workspaceId: string,
    envelopes: components["schemas"]["MemberEnvelopeItem"][],
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/member-envelopes", {
        params: { path: { workspace_id: workspaceId } },
        body: { envelopes },
      }),
    );
  },

  completeKekRotation: async (workspaceId: string, newKekVersion: number) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-rotation/complete", {
        params: { path: { workspace_id: workspaceId } },
        body: { new_kek_version: newKekVersion },
      }),
    );
  },

  getMemberEnvelopeWithPop: async (workspaceId: string) => {
    const result = await client.GET("/api/encryption/workspaces/{workspace_id}/member-envelope", {
      params: { path: { workspace_id: workspaceId } },
    });
    if (result.response.status === 404) return null;
    return throwIfError(result);
  },

  getWorkspaceMemberKeys: async (workspaceId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/member-keys", {
        params: { path: { workspace_id: workspaceId } },
        ...init,
      }),
    ),

  setupComplete: async () => throwIfError(await client.POST("/api/encryption/setup-complete")),

  getDocumentKeys: async (documentId: string, init?: Pick<RequestInit, "signal">) =>
    throwIfError(
      await client.GET("/api/encryption/documents/{document_id}/keys", {
        params: { path: { document_id: documentId } },
        ...init,
      }),
    ),

  createDocumentKey: async (
    documentId: string,
    body: components["schemas"]["CreateDocumentKeyRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/encryption/documents/{document_id}/keys", {
        params: { path: { document_id: documentId } },
        body,
      }),
    ),
};
