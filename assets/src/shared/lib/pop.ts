import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
interface PopHeaders {
  "X-PoP-Device-Id": string;
  "X-PoP-Challenge": string;
  "X-PoP-Signature": string;
}
export class PopChallengeRateLimitError extends Error {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super("pop-challenge failed: rate limited");
    this.name = "PopChallengeRateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
async function popChallenge(
  deviceId: string,
  signal?: AbortSignal,
): Promise<{
  challenge: string;
}> {
  const response = await fetch("/api/auth/pop-challenge", {
    method: "POST",
    credentials: "include",
    headers: {
      "X-PoP-Device-Id": deviceId,
    },
    signal,
  });
  if (response.ok) {
    return (await response.json()) as {
      challenge: string;
    };
  }
  const retryAfterHeader = response.headers.get("retry-after");
  let retryAfterSeconds: number | null = retryAfterHeader ? parseFloat(retryAfterHeader) : null;
  try {
    const errorBody = (await response.json()) as {
      retry_after?: string | number;
    };
    if (typeof errorBody.retry_after === "number" && errorBody.retry_after > 0) {
      retryAfterSeconds = errorBody.retry_after;
    } else if (typeof errorBody.retry_after === "string") {
      const parsed = parseFloat(errorBody.retry_after);
      if (!Number.isNaN(parsed) && parsed > 0) {
        retryAfterSeconds = parsed;
      }
    }
  } catch {
    // Response may not include a JSON body. Fall back to the Retry-After header.
  }
  if (response.status === 429) {
    throw new PopChallengeRateLimitError(retryAfterSeconds ?? 1);
  }
  throw new Error(`pop-challenge failed: ${response.status}`);
}
export async function getPopHeaders(
  deviceIdOverride?: string,
  signal?: AbortSignal,
): Promise<PopHeaders> {
  const worker = getCryptoWorker();
  const deviceId = deviceIdOverride ?? (await worker.getDeviceId());
  const { challenge } = await popChallenge(deviceId, signal);
  const { signature } = await worker.signPop({ challenge, deviceId });
  return {
    "X-PoP-Device-Id": deviceId,
    "X-PoP-Challenge": challenge,
    "X-PoP-Signature": base64UrlEncode(signature),
  };
}
