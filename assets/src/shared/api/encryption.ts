import { client, throwIfError } from "./core";
import type { components } from "./schema";

export const encryptionApi = {
  getWorkspaceIds: async () =>
    throwIfError(
      await client.GET("/api/workspaces/ids"),
    ),

  getWorkspaceKeysWithPop: async (workspaceId: string, deviceId: string) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/keys", {
        params: {
          path: { workspace_id: workspaceId },
          query: { device_id: deviceId },
        },
      }),
    ),

  getKekBackupWithPop: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/kek-backup", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  createWorkspaceKeyWithPop: async (
    workspaceId: string,
    body: components["schemas"]["CreateWorkspaceKeyRequest"],
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/keys", {
        params: { path: { workspace_id: workspaceId } },
        body,
      }),
    );
  },

  createKekBackupWithPop: async (
    workspaceId: string,
    body: components["schemas"]["CreateKekBackupRequest"],
  ) => {
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-backup", {
        params: { path: { workspace_id: workspaceId } },
        body,
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

  completeKekRotation: async (
    workspaceId: string,
    newKekVersion: number,
  ) => {
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

  getWorkspaceMemberKeys: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/member-keys", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  setupComplete: async () =>
    throwIfError(
      await client.POST("/api/encryption/setup-complete"),
    ),
};
