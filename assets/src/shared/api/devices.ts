import { client, throwIfError } from "./core";
import type { components } from "./schema";
import { fetchWithPop } from "@/shared/lib/pop";

export type CreatePendingDeviceRequest = components["schemas"]["CreatePendingDeviceRequest"];
export type ApproveDeviceRequest = components["schemas"]["ApproveDeviceRequest"];

export interface DeviceInfo {
  id: string;
  name: string;
  device_type: string;
  ecdh_public_key: string;
  signing_public_key: string;
  client_nonce: string;
  identity_signature: string | null;
  last_seen_at: string;
  created_at: string;
}

export interface PendingDeviceInfo {
  id: string;
  name: string;
  device_type: string;
  ecdh_public_key: string;
  signing_public_key: string;
  client_nonce: string;
  ip_address: string;
  created_at: string;
  expires_at: string;
}

export interface WorkspaceRotationInfo {
  workspace_id: string;
  current_kek_version: number;
}

export interface RevokeDeviceResult {
  revoked_device_id: string;
  revocation_mode: string;
  workspaces_needing_kek_rotation: WorkspaceRotationInfo[];
}

export const devicesApi = {
  bootstrap: async (body: {
    name: string;
    device_type: string;
    identity_signing_public_key: string;
    device_signing_public_key: string;
    device_ecdh_public_key: string;
    client_nonce: string;
    identity_signature: string;
  }): Promise<{ device_id: string; status: string }> => {
    const res = await fetch("/api/devices/bootstrap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "include",
    });
    if (!res.ok) throw new Error(`bootstrap device failed: ${res.status}`);
    return res.json();
  },

  createPending: async (body: CreatePendingDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/pending", { body }),
    ),

  approve: async (id: string, body: ApproveDeviceRequest): Promise<{ device: { id: string; name: string; device_type: string } }> => {
    const res = await fetchWithPop(`/api/devices/pending/${id}/approve`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`approve device failed: ${res.status}`);
    return res.json();
  },

  approveWithoutPop: async (id: string, body: ApproveDeviceRequest): Promise<{ device: { id: string; name: string; device_type: string } }> => {
    const res = await fetch(`/api/devices/pending/${id}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "include",
    });
    if (!res.ok) throw new Error(`approve device failed: ${res.status}`);
    return res.json();
  },

  list: async (): Promise<{ devices: DeviceInfo[] }> => {
    const res = await fetchWithPop("/api/devices");
    if (!res.ok) throw new Error(`list devices failed: ${res.status}`);
    return res.json();
  },

  listPending: async (): Promise<{ devices: PendingDeviceInfo[] }> => {
    const res = await fetch("/api/devices/pending", {
      credentials: "include",
    });
    if (!res.ok) throw new Error(`list pending failed: ${res.status}`);
    return res.json();
  },

  revoke: async (
    deviceId: string,
    revocationMode: "security" | "retire",
    identitySignature: string,
    revokedAt: number,
  ): Promise<RevokeDeviceResult> => {
    const res = await fetchWithPop(`/api/devices/${deviceId}`, {
      method: "DELETE",
      body: JSON.stringify({
        revocation_mode: revocationMode,
        identity_signature: identitySignature,
        revoked_at: revokedAt,
      }),
    });
    if (!res.ok) throw new Error(`revoke device failed: ${res.status}`);
    return res.json();
  },

  rename: async (deviceId: string, name: string): Promise<void> => {
    const res = await fetchWithPop(`/api/devices/${deviceId}`, {
      method: "PATCH",
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error(`rename device failed: ${res.status}`);
  },

  rejectPending: async (id: string): Promise<void> => {
    const res = await fetch(`/api/devices/pending/${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    if (!res.ok) throw new Error(`reject pending failed: ${res.status}`);
  },

  getPendingStatus: async (id: string): Promise<{ status: string }> => {
    const res = await fetch(`/api/devices/pending/${id}/sas`, {
      credentials: "include",
    });
    if (!res.ok) throw new Error(`get pending status failed: ${res.status}`);
    return res.json();
  },

  distributeUmk: async (
    deviceId: string,
    senderDeviceId: string,
    encryptedUmk: string,
    nonce: string,
  ): Promise<void> => {
    const res = await fetchWithPop(`/api/devices/${deviceId}/keys/umk`, {
      method: "POST",
      body: JSON.stringify({
        sender_device_id: senderDeviceId,
        encrypted_umk: encryptedUmk,
        nonce,
      }),
    });
    if (!res.ok) throw new Error(`distribute umk failed: ${res.status}`);
  },

  getUmk: async (
    deviceId: string,
  ): Promise<{
    encrypted_umk: string;
    nonce: string;
    sender_device_id: string;
    sender_ecdh_public_key: string;
    sender_signing_public_key: string;
  }> => {
    const res = await fetchWithPop(`/api/devices/${deviceId}/keys/umk`);
    if (!res.ok) throw new Error(`get umk failed: ${res.status}`);
    return res.json();
  },
};
