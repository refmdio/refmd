import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { encodeHybridSignatureForTransport } from "@/shared/lib/crypto/signature";
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
  "X-PoP-Actor-Variant": "user_device" | "share_participant_device";
  "X-PoP-Challenge": string;
  "X-PoP-Signature-Transport": string;
}

export interface ChannelPopParams {
  pop_device_id: string;
  pop_actor_variant: "user_device" | "share_participant_device";
  pop_challenge: string;
  pop_signature: StrictJsonValue;
}

type PopScope = "user" | "share";
type PopTransport = "http" | "phoenix_channel";
interface HttpPopResource extends Record<string, string> {
  canonical_query: string;
  method: string;
  path: string;
  query_hash: string;
}

interface ChannelPopResource extends Record<string, string> {
  channel_event: "phx_join";
  document_id: string;
  event_name: "phx_join";
  join_push_kind: "join";
  payload_hash: string;
  scope_kind: "user" | "share";
  share_id: string;
  topic: string;
}

type PopResource = HttpPopResource | ChannelPopResource;
type PopTranscriptObject = Record<string, StrictJsonValue>;

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
  scope: PopScope,
  signal?: AbortSignal,
): Promise<{
  actor: PopTranscriptObject;
  challenge: string;
  session: PopTranscriptObject;
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
      actor: PopTranscriptObject;
      challenge: string;
      session: PopTranscriptObject;
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
  scope: PopScope = getPreferredSessionScope() === "share" ? "share" : "user",
  workerOverride?: CryptoWorkerClient,
  resource?: HttpPopResource,
): Promise<PopHeaders> {
  const proof = await getPopProof(
    deviceIdOverride,
    signal,
    scope,
    "http",
    workerOverride,
    resource,
  );
  return {
    "X-PoP-Device-Id": proof.deviceId,
    "X-PoP-Actor-Variant": proof.actorVariant,
    "X-PoP-Challenge": proof.challenge,
    "X-PoP-Signature-Transport": proof.signatureTransport,
  };
}

export async function getChannelPopParams(
  deviceIdOverride?: string,
  signal?: AbortSignal,
  scope: PopScope = getPreferredSessionScope() === "share" ? "share" : "user",
  workerOverride?: CryptoWorkerClient,
  resource?: ChannelPopResource,
): Promise<ChannelPopParams> {
  const proof = await getPopProof(
    deviceIdOverride,
    signal,
    scope,
    "phoenix_channel",
    workerOverride,
    resource,
  );
  return {
    pop_device_id: proof.deviceId,
    pop_actor_variant: proof.actorVariant,
    pop_challenge: proof.challenge,
    pop_signature: proof.signature,
  };
}

export function buildChannelPopResource(
  documentId: string,
  scope: PopScope,
  shareId?: string | null,
  joinPayload: Record<string, unknown> = {},
): ChannelPopResource {
  return {
    channel_event: "phx_join",
    document_id: documentId,
    event_name: "phx_join",
    join_push_kind: "join",
    payload_hash: blake3Base64Url(canonicalizeStrictBytes(joinPayload as StrictJsonValue)),
    scope_kind: scope,
    share_id: scope === "share" ? (shareId ?? "") : "none",
    topic: `document:${documentId}`,
  };
}

async function getPopProof(
  deviceIdOverride: string | undefined,
  signal: AbortSignal | undefined,
  scope: PopScope,
  transport: PopTransport,
  workerOverride?: CryptoWorkerClient,
  resource?: PopResource,
): Promise<{
  actorVariant: "user_device" | "share_participant_device";
  challenge: string;
  deviceId: string;
  signature: StrictJsonValue;
  signatureTransport: string;
}> {
  return enqueuePopChallenge(async () => {
    const worker = workerOverride ?? getCryptoWorker();
    const deviceId = deviceIdOverride ?? (await worker.getDeviceId());
    await waitForPopRateLimit(signal);
    try {
      const { actor, challenge, session } = await popChallenge(deviceId, scope, signal);
      if (!resource) {
        throw new Error(
          transport === "http" ? "pop_http_resource_required" : "pop_channel_resource_required",
        );
      }
      const { signature } = await worker.createPopSignature({
        challenge,
        deviceId,
        scope,
        transport,
        actor,
        session,
        resource,
      });
      return {
        actorVariant: scope === "share" ? "share_participant_device" : "user_device",
        challenge,
        deviceId,
        signature: signature as unknown as StrictJsonValue,
        signatureTransport: encodeHybridSignatureForTransport(signature),
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
