import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker, type CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
import {
  clearAuthTransportNetworkFailure,
  recordAuthTransportNetworkFailure,
  recordAuthTransportRateLimit,
  waitForAuthTransport,
} from "@/shared/lib/ws/transport-coordinator";
import { getPreferredSessionScope, SHARE_SESSION_SCOPE_HEADER } from "./session-scope";
import { AuthUnauthorizedError } from "./unauthorized";

interface PopHeaders {
  "X-PoP-Device-Id": string;
  "X-PoP-Challenge": string;
  "X-PoP-Signature": string;
}

let popRateLimitedUntil = 0;
let popChallengeQueue: Promise<void> = Promise.resolve();

export class PopChallengeRateLimitError extends Error {
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super("pop-challenge failed: rate limited");
    this.name = "PopChallengeRateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(createAbortError());
  }
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timeout);
      reject(createAbortError());
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function createAbortError(): Error {
  const error = new Error("request_aborted");
  error.name = "AbortError";
  return error;
}

async function waitForPopRateLimit(signal?: AbortSignal): Promise<void> {
  await waitForAuthTransport(signal);
  const remaining = popRateLimitedUntil - Date.now();
  if (remaining > 0) {
    await sleep(remaining + Math.random() * 200, signal);
  }
}

function setPopRateLimit(retryAfterSeconds: number): void {
  const until = Date.now() + Math.max(1, retryAfterSeconds) * 1000;
  if (until > popRateLimitedUntil) {
    popRateLimitedUntil = until;
  }
  recordAuthTransportRateLimit(Math.max(1, retryAfterSeconds) * 1000);
}

async function enqueuePopChallenge<T>(fn: () => Promise<T>): Promise<T> {
  const previous = popChallengeQueue;
  let releaseQueue: () => void = () => {};
  popChallengeQueue = new Promise<void>((resolve) => {
    releaseQueue = resolve;
  });
  await previous.catch(() => {});
  try {
    return await fn();
  } finally {
    releaseQueue();
  }
}

async function popChallenge(
  deviceId: string,
  scope: "user" | "share",
  signal?: AbortSignal,
): Promise<{
  challenge: string;
}> {
  const response = await fetch("/api/auth/pop-challenge", {
    method: "POST",
    credentials: "include",
    headers: {
      "X-PoP-Device-Id": deviceId,
      ...(scope === "share" ? { [SHARE_SESSION_SCOPE_HEADER]: "share" } : {}),
    },
    signal,
  });
  if (response.ok) {
    clearAuthTransportNetworkFailure();
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
  if (response.status === 401) {
    throw new AuthUnauthorizedError(scope, `pop-challenge failed: ${response.status}`);
  }
  throw new Error(`pop-challenge failed: ${response.status}`);
}

export async function getPopHeaders(
  deviceIdOverride?: string,
  signal?: AbortSignal,
  scope: "user" | "share" = getPreferredSessionScope() === "share" ? "share" : "user",
  workerOverride?: CryptoWorkerClient,
): Promise<PopHeaders> {
  return enqueuePopChallenge(async () => {
    const worker = workerOverride ?? getCryptoWorker();
    const deviceId = deviceIdOverride ?? (await worker.getDeviceId());
    await waitForPopRateLimit(signal);
    try {
      const { challenge } = await popChallenge(deviceId, scope, signal);
      const { signature } = await worker.signPop({ challenge, deviceId });
      return {
        "X-PoP-Device-Id": deviceId,
        "X-PoP-Challenge": challenge,
        "X-PoP-Signature": base64UrlEncode(signature),
      };
    } catch (error) {
      if (error instanceof TypeError) {
        recordAuthTransportNetworkFailure();
      } else if (error instanceof PopChallengeRateLimitError) {
        setPopRateLimit(error.retryAfterSeconds);
      }
      throw error;
    }
  });
}
