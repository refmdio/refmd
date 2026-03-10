import { client, throwIfError } from "./core";

export const trustTransferApi = {
  requestNonce: async (deviceId: string) =>
    throwIfError(
      await client.POST("/api/trust-transfer/nonce", {
        body: { device_id: deviceId },
      }),
    ),

  submitState: async (body: {
    target_device_id: string;
    transfer_nonce: string;
    ciphertext: string;
    nonce: string;
    signature: string;
  }) => {
    throwIfError(
      await client.POST("/api/trust-transfer/state", {
        body,
      }),
    );
  },

  retrieveState: async (deviceId: string) =>
    throwIfError(
      await client.GET("/api/trust-transfer/state", {
        params: { query: { device_id: deviceId } },
      }),
    ),
};
