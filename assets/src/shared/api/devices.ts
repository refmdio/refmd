import { client, throwIfError, POP_DEVICE_OVERRIDE_HEADER } from "./core";
import type { components } from "./schema";

type CreateDeviceRegistrationRequest = components["schemas"]["CreateDeviceRegistrationRequest"];
type ApproveDeviceRequest = components["schemas"]["ApproveDeviceRequest"];

export type DeviceInfo = components["schemas"]["DeviceFullInfo"];

export interface DeviceRegistrationInfo {
  id: string;
  name: string;
  device_type: string;
  ecdh_public_key: string;
  signing_public_key: string;
  client_nonce: string;
  ip_address?: string | null;
  created_at: string;
  expires_at: string;
}

export interface WorkspaceRotationInfo {
  workspace_id: string;
  current_kek_version: number;
}

export const devicesApi = {
  bootstrap: async (body: components["schemas"]["BootstrapDeviceRequest"]) =>
    throwIfError(await client.POST("/api/devices/bootstrap", { body })),

  createRegistration: async (body: CreateDeviceRegistrationRequest) =>
    throwIfError(await client.POST("/api/devices/registrations", { body })),

  approve: async (id: string, body: ApproveDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/registrations/{id}/approve", {
        params: { path: { id } },
        body,
      }),
    ),

  list: async (opts?: { popDeviceId?: string }) => {
    const fetchOpts = opts?.popDeviceId
      ? { headers: { [POP_DEVICE_OVERRIDE_HEADER]: opts.popDeviceId } }
      : undefined;
    return throwIfError(await client.GET("/api/devices", fetchOpts));
  },

  listRegistrations: async () => throwIfError(await client.GET("/api/devices/registrations")),

  revoke: async (
    deviceId: string,
    revocationMode: "security" | "retire",
    identitySignature: string,
    revokedAt: number,
  ) =>
    throwIfError(
      await client.DELETE("/api/devices/{device_id}", {
        params: { path: { device_id: deviceId } },
        body: {
          revocation_mode: revocationMode,
          identity_signature: identitySignature,
          revoked_at: revokedAt,
        },
      }),
    ),

  rename: async (deviceId: string, name: string) => {
    throwIfError(
      await client.PATCH("/api/devices/{device_id}", {
        params: { path: { device_id: deviceId } },
        body: { name },
      }),
    );
  },

  rejectRegistration: async (id: string) => {
    throwIfError(
      await client.DELETE("/api/devices/registrations/{id}", {
        params: { path: { id } },
      }),
    );
  },

  getRegistrationSas: async (id: string) =>
    throwIfError(
      await client.GET("/api/devices/registrations/{id}/sas", {
        params: { path: { id } },
      }),
    ),

  distributeUmk: async (
    deviceId: string,
    senderDeviceId: string,
    encryptedUmk: string,
    nonce: string,
  ) => {
    throwIfError(
      await client.POST("/api/devices/{device_id}/keys/umk", {
        params: { path: { device_id: deviceId } },
        body: {
          sender_device_id: senderDeviceId,
          encrypted_umk: encryptedUmk,
          nonce,
        },
      }),
    );
  },

  getUmk: async (deviceId: string, opts?: { popDeviceId?: string }) => {
    const headers = opts?.popDeviceId
      ? { [POP_DEVICE_OVERRIDE_HEADER]: opts.popDeviceId }
      : undefined;
    return throwIfError(
      await client.GET("/api/devices/{device_id}/keys/umk", {
        params: { path: { device_id: deviceId } },
        ...(headers ? { headers } : {}),
      }),
    );
  },
};
