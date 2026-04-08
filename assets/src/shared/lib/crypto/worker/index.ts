// Crypto Worker entry point.
// This file is the Dedicated Worker script, bundled separately by Vite.
// All crypto libraries are imported here and never in the main thread.

import type { CryptoRequest, CryptoResponse, CryptoErrorCode } from "./types";
import { createInitialState } from "./state";
import { handleRequest } from "./handler/index";
import { CryptoOperationError } from "./operation-error";

// In a Dedicated Worker, `self` is DedicatedWorkerGlobalScope.
// We cast to a minimal interface to avoid needing the WebWorker lib
// (which conflicts with DOM lib in the shared tsconfig).
const workerSelf = self as unknown as {
  onmessage: ((event: MessageEvent) => void) | null;
  postMessage(message: unknown, transfer?: Transferable[]): void;
};
const state = createInitialState();

// Token bucket rate limiter.
// Each bucket has a steady-state rate (tokensPerSec) and a burst cap.
// Tokens accumulate up to the burst cap when idle, allowing short spikes.
interface TokenBucket {
  tokens: number;
  lastRefill: number;
  rate: number; // tokens per millisecond
  burst: number;
}

interface RateLimitRule {
  tokensPerSec: number;
  burst: number;
}

const RATE_LIMITS: { exact: Record<string, RateLimitRule>; prefix: [string, RateLimitRule][] } = {
  exact: {
    "derive-auth-keys": { tokensPerSec: 0.1, burst: 2 },
  },
  prefix: [
    ["decrypt-", { tokensPerSec: 100, burst: 500 }],
    ["sign-", { tokensPerSec: 50, burst: 100 }],
  ],
};
const DEFAULT_RULE: RateLimitRule = { tokensPerSec: 200, burst: 400 };

function resolveRule(type: string): RateLimitRule {
  const exact = RATE_LIMITS.exact[type];
  if (exact) return exact;
  for (const [prefix, rule] of RATE_LIMITS.prefix) {
    if (type.startsWith(prefix)) return rule;
  }
  return DEFAULT_RULE;
}

const buckets = new Map<string, TokenBucket>();

function checkRateLimit(type: string): boolean {
  const rule = resolveRule(type);
  const now = Date.now();
  let bucket = buckets.get(type);
  if (!bucket) {
    bucket = {
      tokens: rule.burst,
      lastRefill: now,
      rate: rule.tokensPerSec / 1000,
      burst: rule.burst,
    };
    buckets.set(type, bucket);
  }
  const elapsed = now - bucket.lastRefill;
  bucket.tokens = Math.min(bucket.burst, bucket.tokens + elapsed * bucket.rate);
  bucket.lastRefill = now;
  if (bucket.tokens < 1) return false;
  bucket.tokens -= 1;
  return true;
}

workerSelf.onmessage = async (event: MessageEvent<CryptoRequest>) => {
  const request = event.data;

  if (request.type === "lock" || request.type === "is-ready") {
    const result = await handleRequest(state, request);
    respond(request.id, result);
    return;
  }

  if (!checkRateLimit(request.type)) {
    respondError(request.id, "rate_limited", `Rate limited: ${request.type}`);
    return;
  }

  try {
    const result = await handleRequest(state, request);
    respond(request.id, result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    const code: CryptoErrorCode =
      error instanceof CryptoOperationError ? error.code : "internal_error";
    respondError(request.id, code, message);
  }
};

function respond(id: string, payload: unknown, transfer?: Transferable[]): void {
  const response: CryptoResponse = { id, type: "success", payload };
  if (transfer?.length) {
    workerSelf.postMessage(response, transfer);
  } else {
    workerSelf.postMessage(response);
  }
}

function respondError(id: string, code: CryptoErrorCode, message: string): void {
  const response: CryptoResponse = {
    id,
    type: "error",
    payload: { code, message },
  };
  workerSelf.postMessage(response);
}
