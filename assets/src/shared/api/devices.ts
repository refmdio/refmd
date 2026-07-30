import { client, throwIfError, RRP_DEVICE_OVERRIDE_HEADER, withUserRrpParams } from "./core";
import type { components } from "./schema";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { GenesisCompoundAuthorization } from "@/shared/lib/crypto/genesis-authorization";

type CreateDeviceRegistrationRequest = components["schemas"]["CreateDeviceRegistrationRequest"];
type ApproveDeviceRequest = components["schemas"]["ApproveDeviceRequest"];
export type { ApproveDeviceRequest };
type DeviceRevocationCommand = components["schemas"]["DeviceRevocationCommand"];
type DeviceRevocationAuthorization = components["schemas"]["DeviceRevocationAuthorization"];
type DistributeUmkRequest = components["schemas"]["DistributeUmkRequest"];

export type DeviceInfo = components["schemas"]["DeviceFullInfo"];
export type DeviceRegistrationInfo = components["schemas"]["DeviceRegistrationInfo"];

export interface WorkspaceRotationInfo {
  workspace_id: string;
  current_kek_version: number;
  kek_rotation_initiator_user_id?: string | null;
  rotation_id?: string | null;
  pending_kek_version?: number | null;
}

export interface GenesisCommitResponse {
  status: "committed";
  user_id: string;
  device_id: string;
  workspace_id: string;
  user_audit_checkpoint_hash: string;
  workspace_audit_checkpoint_hash: string;
}

export const devicesApi = {
  bootstrapChallenge: async () =>
    throwIfError(
      await client.POST("/api/devices/bootstrap/challenge", {
        headers: { "Content-Type": "application/json" },
      }),
    ),

  bootstrapIntent: async (body: StrictJsonValue): Promise<StrictJsonValue> =>
    throwIfError(
      await client.POST("/api/devices/bootstrap/intent", { body } as never),
    ) as StrictJsonValue,

  bootstrap: async (body: GenesisCompoundAuthorization): Promise<GenesisCommitResponse> =>
    throwIfError(
      await client.POST("/api/devices/bootstrap", {
        body: body as never,
      }),
    ) as unknown as GenesisCommitResponse,

  registrationChallenge: async (init?: Pick<RequestInit, "signal">) =>
    throwIfError(await client.POST("/api/devices/registrations/challenge", { ...init })),

  createRegistration: async (
    body: CreateDeviceRegistrationRequest,
    init?: Pick<RequestInit, "signal">,
  ) => throwIfError(await client.POST("/api/devices/registrations", { body, ...init })),

  approve: async (id: string, body: ApproveDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/registrations/{device_id}/approve", {
        params: withUserRrpParams({ path: { device_id: id } }),
        body,
      }),
    ),

  approveRecovered: async (id: string, body: ApproveDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/registrations/{device_id}/approve", {
        params: { path: { device_id: id } },
        body,
      }),
    ),

  list: async (opts?: { rrpDeviceId?: string }) => {
    const fetchOpts = opts?.rrpDeviceId
      ? { headers: { [RRP_DEVICE_OVERRIDE_HEADER]: opts.rrpDeviceId } }
      : undefined;
    return throwIfError(
      await client.GET("/api/devices", {
        params: withUserRrpParams(),
        ...fetchOpts,
      }),
    );
  },

  listRegistrations: async () => throwIfError(await client.GET("/api/devices/registrations")),

  revocationIntent: async (deviceId: string, body: DeviceRevocationCommand) =>
    throwIfError(
      await client.POST("/api/devices/{device_id}/revocation/intent", {
        params: withUserRrpParams({ path: { device_id: deviceId } }),
        body,
      }),
    ),

  revoke: async (deviceId: string, body: DeviceRevocationAuthorization) =>
    throwIfError(
      await client.DELETE("/api/devices/{device_id}", {
        params: withUserRrpParams({ path: { device_id: deviceId } }),
        body,
      }),
    ),

  rename: async (deviceId: string, name: string) => {
    throwIfError(
      await client.PATCH("/api/devices/{device_id}", {
        params: withUserRrpParams({ path: { device_id: deviceId } }),
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

  getInitialAkeOffers: async (deviceId: string) =>
    throwIfError(
      await client.GET("/api/devices/registrations/{device_id}/initial-ake-offers", {
        params: { path: { device_id: deviceId } },
      }),
    ),

  submitInitialAkeResponses: async (
    deviceId: string,
    body: components["schemas"]["InitialAkeResponsesRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/devices/registrations/{device_id}/initial-ake-responses", {
        params: { path: { device_id: deviceId } },
        body,
      }),
    ),

  getInitialAkeResponses: async (deviceId: string) =>
    throwIfError(
      await client.GET("/api/devices/{device_id}/initial-ake-responses", {
        params: withUserRrpParams({ path: { device_id: deviceId } }),
      }),
    ),

  distributeUmk: async (
    deviceId: string,
    senderDeviceId: string,
    keyDelivery: Omit<DistributeUmkRequest, "sender_device_id">,
  ) => {
    throwIfError(
      await client.POST("/api/devices/{device_id}/keys/umk", {
        params: withUserRrpParams({ path: { device_id: deviceId } }),
        body: {
          sender_device_id: senderDeviceId,
          ...keyDelivery,
        },
      }),
    );
  },

  getUmk: async (deviceId: string, opts?: { rrpDeviceId?: string }) => {
    const headers = opts?.rrpDeviceId
      ? { [RRP_DEVICE_OVERRIDE_HEADER]: opts.rrpDeviceId }
      : undefined;
    return throwIfError(
      await client.GET("/api/devices/{device_id}/keys/umk", {
        params: withUserRrpParams({ path: { device_id: deviceId } }),
        ...(headers ? { headers } : {}),
      }),
    );
  },
};
