import { fetchWithPop } from "@/shared/lib/pop";

export const trustTransferApi = {
  requestNonce: async (
    deviceId: string,
  ): Promise<{ nonce: string; expires_at: string }> => {
    const res = await fetch("/api/trust-transfer/nonce", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId }),
    });
    if (!res.ok) throw new Error(`request nonce failed: ${res.status}`);
    return res.json();
  },

  submitState: async (body: {
    target_device_id: string;
    transfer_nonce: string;
    ciphertext: string;
    nonce: string;
    signature: string;
  }): Promise<void> => {
    const res = await fetchWithPop("/api/trust-transfer/state", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`submit trust state failed: ${res.status}`);
  },

  retrieveState: async (
    deviceId: string,
  ): Promise<{
    sender_device_id: string;
    sender_ecdh_public_key: string;
    sender_signing_public_key: string;
    ciphertext: string;
    nonce: string;
    signature: string;
  }> => {
    const res = await fetch(
      `/api/trust-transfer/state?device_id=${encodeURIComponent(deviceId)}`,
      {
        method: "GET",
        credentials: "include",
      },
    );
    if (!res.ok) throw new Error(`retrieve trust state failed: ${res.status}`);
    return res.json();
  },
};
