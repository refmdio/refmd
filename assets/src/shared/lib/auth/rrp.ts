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

interface RrpHeaders {
  "X-RefMD-RRP-Device-Id": string;
  "X-RefMD-RRP-Actor-Variant": "user_device" | "share_participant_device";
  "X-RefMD-RRP-Challenge": string;
  "X-RefMD-RRP-Signature-Transport": string;
}

export interface ChannelRrpParams {
  rrp_device_id: string;
  rrp_actor_variant: "user_device" | "share_participant_device";
  rrp_challenge: string;
  rrp_signature: StrictJsonValue;
}

type RrpScope = "user" | "share";
type RrpTransport = "http" | "phoenix_channel";
interface HttpRrpResource extends Record<string, string> {
  canonical_query: string;
  method: string;
  path: string;
  query_hash: string;
}

interface ChannelRrpResource extends Record<string, string> {
  channel_event: "phx_join";
  document_id: string;
  event_name: "phx_join";
  join_push_kind: "join";
  payload_hash: string;
  scope_kind: "user" | "share";
  share_id: string;
  topic: string;
}

type RrpResource = HttpRrpResource | ChannelRrpResource;
type RrpTranscriptObject = Record<string, StrictJsonValue>;

let rrpRateLimitedUntil = 0;
let rrpChallengeQueue: Promise<void> = Promise.resolve();

export class RrpChallengeRateLimitError extends Error {
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super("rrp-challenge failed: rate limited");
    this.name = "RrpChallengeRateLimitError";
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

async function waitForRrpRateLimit(signal?: AbortSignal): Promise<void> {
  await waitForAuthTransport(signal);
  const remaining = rrpRateLimitedUntil - Date.now();
  if (remaining > 0) {
    await sleep(remaining + Math.random() * 200, signal);
  }
}

function setRrpRateLimit(retryAfterSeconds: number): void {
  const until = Date.now() + Math.max(1, retryAfterSeconds) * 1000;
  if (until > rrpRateLimitedUntil) {
    rrpRateLimitedUntil = until;
  }
  recordAuthTransportRateLimit(Math.max(1, retryAfterSeconds) * 1000);
}

async function enqueueRrpChallenge<T>(fn: () => Promise<T>): Promise<T> {
  const previous = rrpChallengeQueue;
  let releaseQueue: () => void = () => {};
  rrpChallengeQueue = new Promise<void>((resolve) => {
    releaseQueue = resolve;
  });
  await previous.catch(() => {});
  try {
    return await fn();
  } finally {
    releaseQueue();
  }
}

async function rrpChallenge(
  deviceId: string,
  scope: RrpScope,
  signal?: AbortSignal,
): Promise<{
  actor: RrpTranscriptObject;
  challenge: string;
  session: RrpTranscriptObject;
}> {
  const response = await fetch("/api/auth/rrp-challenge", {
    method: "POST",
    credentials: "include",
    headers: {
      "X-RefMD-RRP-Device-Id": deviceId,
      ...(scope === "share" ? { [SHARE_SESSION_SCOPE_HEADER]: "share" } : {}),
    },
    signal,
  });
  if (response.ok) {
    clearAuthTransportNetworkFailure();
    return (await response.json()) as {
      actor: RrpTranscriptObject;
      challenge: string;
      session: RrpTranscriptObject;
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
    throw new RrpChallengeRateLimitError(retryAfterSeconds ?? 1);
  }
  if (response.status === 401) {
    throw new AuthUnauthorizedError(scope, `rrp-challenge failed: ${response.status}`);
  }
  throw new Error(`rrp-challenge failed: ${response.status}`);
}

export async function getRrpHeaders(
  deviceIdOverride?: string,
  signal?: AbortSignal,
  scope: RrpScope = getPreferredSessionScope() === "share" ? "share" : "user",
  workerOverride?: CryptoWorkerClient,
  resource?: HttpRrpResource,
): Promise<RrpHeaders> {
  const proof = await getRrpProof(
    deviceIdOverride,
    signal,
    scope,
    "http",
    workerOverride,
    resource,
  );
  return {
    "X-RefMD-RRP-Device-Id": proof.deviceId,
    "X-RefMD-RRP-Actor-Variant": proof.actorVariant,
    "X-RefMD-RRP-Challenge": proof.challenge,
    "X-RefMD-RRP-Signature-Transport": proof.signatureTransport,
  };
}

export async function getChannelRrpParams(
  deviceIdOverride?: string,
  signal?: AbortSignal,
  scope: RrpScope = getPreferredSessionScope() === "share" ? "share" : "user",
  workerOverride?: CryptoWorkerClient,
  resource?: ChannelRrpResource,
): Promise<ChannelRrpParams> {
  const proof = await getRrpProof(
    deviceIdOverride,
    signal,
    scope,
    "phoenix_channel",
    workerOverride,
    resource,
  );
  return {
    rrp_device_id: proof.deviceId,
    rrp_actor_variant: proof.actorVariant,
    rrp_challenge: proof.challenge,
    rrp_signature: proof.signature,
  };
}

export function buildChannelRrpResource(
  documentId: string,
  scope: RrpScope,
  shareId?: string | null,
  joinPayload: Record<string, unknown> = {},
): ChannelRrpResource {
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

async function getRrpProof(
  deviceIdOverride: string | undefined,
  signal: AbortSignal | undefined,
  scope: RrpScope,
  transport: RrpTransport,
  workerOverride?: CryptoWorkerClient,
  resource?: RrpResource,
): Promise<{
  actorVariant: "user_device" | "share_participant_device";
  challenge: string;
  deviceId: string;
  signature: StrictJsonValue;
  signatureTransport: string;
}> {
  return enqueueRrpChallenge(async () => {
    const worker = workerOverride ?? getCryptoWorker();
    const deviceId = deviceIdOverride ?? (await worker.getDeviceId());
    await waitForRrpRateLimit(signal);
    try {
      const { actor, challenge, session } = await rrpChallenge(deviceId, scope, signal);
      if (!resource) {
        throw new Error(
          transport === "http" ? "rrp_http_resource_required" : "rrp_channel_resource_required",
        );
      }
      const { signature } = await worker.createRrpSignature({
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
      } else if (error instanceof RrpChallengeRateLimitError) {
        setRrpRateLimit(error.retryAfterSeconds);
      }
      throw error;
    }
  });
}
