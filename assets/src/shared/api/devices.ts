import { client, throwIfError, POP_DEVICE_OVERRIDE_HEADER, withUserPopParams } from "./core";
import type { components } from "./schema";

type CreateDeviceRegistrationRequest = components["schemas"]["CreateDeviceRegistrationRequest"];
type ApproveDeviceRequest = components["schemas"]["ApproveDeviceRequest"];
export type { ApproveDeviceRequest };
type RevokeDeviceRequest = components["schemas"]["RevokeDeviceRequest"];
type DistributeUmkRequest = components["schemas"]["DistributeUmkRequest"];

export type DeviceInfo = components["schemas"]["DeviceFullInfo"];
export type DeviceRegistrationInfo = components["schemas"]["DeviceRegistrationInfo"];

export interface WorkspaceRotationInfo {
  workspace_id: string;
  current_kek_version: number;
}

export const devicesApi = {
  bootstrapChallenge: async () =>
    throwIfError(await client.POST("/api/devices/bootstrap/challenge", {})),

  bootstrap: async (body: components["schemas"]["BootstrapDeviceRequest"]) =>
    throwIfError(await client.POST("/api/devices/bootstrap", { body })),

  registrationChallenge: async () =>
    throwIfError(await client.POST("/api/devices/registrations/challenge", {})),

  createRegistration: async (body: CreateDeviceRegistrationRequest) =>
    throwIfError(await client.POST("/api/devices/registrations", { body })),

  approve: async (id: string, body: ApproveDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/registrations/{device_id}/approve", {
        params: withUserPopParams({ path: { device_id: id } }),
        body,
      }),
    ),

  list: async (opts?: { popDeviceId?: string }) => {
    const fetchOpts = opts?.popDeviceId
      ? { headers: { [POP_DEVICE_OVERRIDE_HEADER]: opts.popDeviceId } }
      : undefined;
    return throwIfError(
      await client.GET("/api/devices", {
        params: withUserPopParams(),
        ...fetchOpts,
      }),
    );
  },

  listRegistrations: async () => throwIfError(await client.GET("/api/devices/registrations")),

  revoke: async (
    deviceId: string,
    revocationMode: "security" | "retire",
    revocationSignature: RevokeDeviceRequest["revocation_signature"],
    revokedAt: number,
    keyDirectory: Pick<
      RevokeDeviceRequest,
      | "user_key_directory_events"
      | "user_key_directory_checkpoint"
      | "workspace_key_directory_appends"
    >,
  ) =>
    throwIfError(
      await client.DELETE("/api/devices/{device_id}", {
        params: withUserPopParams({ path: { device_id: deviceId } }),
        body: {
          revocation_mode: revocationMode,
          revocation_signature: revocationSignature,
          revoked_at: revokedAt,
          ...keyDirectory,
        },
      }),
    ),

  rename: async (deviceId: string, name: string) => {
    throwIfError(
      await client.PATCH("/api/devices/{device_id}", {
        params: withUserPopParams({ path: { device_id: deviceId } }),
        body: { name },
      }),
    );
  },

  rejectRegistration: async (id: string) => {
    throwIfError(
      await client.DELETE("/api/devices/registrations/{device_id}", {
        params: { path: { device_id: id } },
      }),
    );
  },

  getRegistrationSas: async (id: string) =>
    throwIfError(
      await client.GET("/api/devices/registrations/{device_id}/sas", {
        params: { path: { device_id: id } },
      }),
    ),

  distributeUmk: async (
    deviceId: string,
    senderDeviceId: string,
    keyDelivery: Omit<DistributeUmkRequest, "sender_device_id">,
  ) => {
    throwIfError(
      await client.POST("/api/devices/{device_id}/keys/umk", {
        params: withUserPopParams({ path: { device_id: deviceId } }),
        body: {
          sender_device_id: senderDeviceId,
          ...keyDelivery,
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
        params: withUserPopParams({ path: { device_id: deviceId } }),
        ...(headers ? { headers } : {}),
      }),
    );
  },
};
