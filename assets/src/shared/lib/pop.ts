import { authApi } from "@/shared/api/auth";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export interface PopHeaders {
  "X-PoP-Device-Id": string;
  "X-PoP-Challenge": string;
  "X-PoP-Signature": string;
}

export async function getPopHeaders(deviceIdOverride?: string): Promise<PopHeaders> {
  const worker = getCryptoWorker();

  const deviceId = deviceIdOverride ?? (await worker.getDeviceId());

  const { challenge } = await authApi.popChallenge(deviceId);

  const { signature } = await worker.signPop({ challenge, deviceId });

  return {
    "X-PoP-Device-Id": deviceId,
    "X-PoP-Challenge": challenge,
    "X-PoP-Signature": base64UrlEncode(signature),
  };
}
