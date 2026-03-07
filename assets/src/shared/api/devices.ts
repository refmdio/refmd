import { client, throwIfError } from "./core";
import type { components } from "./schema";

export type CreatePendingDeviceRequest = components["schemas"]["CreatePendingDeviceRequest"];
export type ApproveDeviceRequest = components["schemas"]["ApproveDeviceRequest"];

export const devicesApi = {
  createPending: async (body: CreatePendingDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/pending", { body }),
    ),

  approve: async (id: string, body: ApproveDeviceRequest) =>
    throwIfError(
      await client.POST("/api/devices/pending/{id}/approve", {
        params: { path: { id } },
        body,
      }),
    ),
};
