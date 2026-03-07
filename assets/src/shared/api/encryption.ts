import { client, throwIfError } from "./core";
import type { components } from "./schema";

export type CreateWorkspaceKeyRequest = components["schemas"]["CreateWorkspaceKeyRequest"];
export type CreateKekBackupRequest = components["schemas"]["CreateKekBackupRequest"];

export const encryptionApi = {
  createWorkspaceKey: async (workspaceId: string, body: CreateWorkspaceKeyRequest) =>
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/keys", {
        params: { path: { workspace_id: workspaceId } },
        body,
      }),
    ),

  getWorkspaceKeys: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/keys", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  createKekBackup: async (workspaceId: string, body: CreateKekBackupRequest) =>
    throwIfError(
      await client.POST("/api/encryption/workspaces/{workspace_id}/kek-backup", {
        params: { path: { workspace_id: workspaceId } },
        body,
      }),
    ),

  getKekBackup: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/encryption/workspaces/{workspace_id}/kek-backup", {
        params: { path: { workspace_id: workspaceId } },
      }),
    ),

  setupComplete: async () =>
    throwIfError(
      await client.POST("/api/encryption/setup-complete"),
    ),
};
