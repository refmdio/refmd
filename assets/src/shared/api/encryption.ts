import { client, throwIfError } from "./core";
import { fetchWithPop } from "@/shared/lib/pop";

export const encryptionApi = {
  getWorkspaceIds: async (): Promise<{ workspace_ids: string[] }> => {
    const res = await fetchWithPop("/api/workspaces/ids");
    if (!res.ok) throw new Error(`get workspace ids failed: ${res.status}`);
    return res.json();
  },

  getWorkspaceKeysWithPop: async (workspaceId: string, deviceId: string): Promise<{
    current_kek_version: number;
    keys: Array<{
      key_version: number;
      encrypted_kek: string;
      nonce: string;
      sender_device_id: string;
      sender_ecdh_public_key: string;
      sender_signing_public_key: string;
    }>;
  }> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/keys?device_id=${encodeURIComponent(deviceId)}`);
    if (!res.ok) throw new Error(`get workspace keys failed: ${res.status}`);
    return res.json();
  },

  getKekBackupWithPop: async (workspaceId: string): Promise<{
    key_version: number;
    encrypted_kek: string;
    nonce: string;
  }> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/kek-backup`);
    if (!res.ok) throw new Error(`get kek backup failed: ${res.status}`);
    return res.json();
  },

  createWorkspaceKeyWithPop: async (
    workspaceId: string,
    body: Record<string, unknown>,
  ): Promise<void> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/keys`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`create workspace key failed: ${res.status}`);
  },

  createKekBackupWithPop: async (
    workspaceId: string,
    body: Record<string, unknown>,
  ): Promise<void> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/kek-backup`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`create kek backup failed: ${res.status}`);
  },

  saveMemberEnvelopes: async (
    workspaceId: string,
    envelopes: Array<{
      target_user_id: string;
      key_version: number;
      sender_device_id: string;
      encrypted_kek: string;
      nonce: string;
    }>,
  ): Promise<void> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/member-envelopes`, {
      method: "POST",
      body: JSON.stringify({ envelopes }),
    });
    if (!res.ok) throw new Error(`save member envelopes failed: ${res.status}`);
  },

  completeKekRotation: async (
    workspaceId: string,
    newKekVersion: number,
  ): Promise<void> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/kek-rotation/complete`, {
      method: "POST",
      body: JSON.stringify({ new_kek_version: newKekVersion }),
    });
    if (!res.ok) throw new Error(`complete kek rotation failed: ${res.status}`);
  },

  getMemberEnvelopeWithPop: async (workspaceId: string): Promise<{
    key_version: number;
    encrypted_kek: string;
    nonce: string;
    sender_device_id: string;
    sender_ecdh_public_key: string;
    sender_signing_public_key: string | null;
  } | null> => {
    const res = await fetchWithPop(`/api/encryption/workspaces/${workspaceId}/member-envelope`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`get member envelope failed: ${res.status}`);
    return res.json();
  },

  setupComplete: async () =>
    throwIfError(
      await client.POST("/api/encryption/setup-complete"),
    ),
};
