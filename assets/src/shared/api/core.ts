import createClient from "openapi-fetch";
import type { paths } from "./schema";
import { CryptoWorkerError } from "@/shared/lib/crypto/worker/client";
import { RrpChallengeRateLimitError } from "@/shared/lib/auth/rrp";
import {
  getPreferredSessionScope,
  SHARE_SESSION_SCOPE_HEADER,
} from "@/shared/lib/auth/session-scope";
import {
  isAuthUnauthorizedError,
  notifyAuthUnauthorized,
  setAuthUnauthorizedHandler,
  type AuthSessionScope,
} from "@/shared/lib/auth/unauthorized";
import {
  clearAuthTransportNetworkFailure,
  recordAuthTransportNetworkFailure,
  recordAuthTransportRateLimit,
  waitForAuthTransport,
} from "@/shared/lib/ws/transport-coordinator";
import { canonicalQueryString } from "@/shared/lib/crypto/canonical-query";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { clientError } from "@/shared/lib/logger";

function isSessionOnlyEndpoint(url: string, method: string): boolean {
  const path = new URL(url, "http://localhost").pathname;
  // Auth: session-only subset (excludes PATCH /auth/password, PUT /auth/recovery-key)
  if (
    path === "/api/auth/me" ||
    path === "/api/auth/logout" ||
    path === "/api/auth/verify-key" ||
    path === "/api/auth/external-accounts" ||
    path === "/api/auth/rrp-challenge" ||
    path === "/api/auth/ws-token" ||
    path === "/api/auth/kdf-migration" ||
    path === "/api/auth/recovery" ||
    path === "/api/auth/password-set" ||
    path === "/api/auth/oauth/crypto-setup" ||
    path === "/api/auth/salt" ||
    path === "/api/auth/login" ||
    path === "/api/auth/register" ||
    /^\/api\/auth\/oauth\/(google|github)\/start$/.test(path)
  ) {
    return true;
  }
  // Device: bootstrap
  if (path === "/api/devices/bootstrap") return true;
  // Device: registration endpoints (session-only), EXCEPT POST .../approve (Recovery-or-RRP)
  if (path.startsWith("/api/devices/registrations")) {
    if (method === "POST" && path.endsWith("/approve")) return false;
    return true;
  }
  // Encryption setup (initial, before RRP is possible)
  if (path === "/api/encryption/setup-complete") return true;
  // Share mount creation is user-session scoped; do not issue share-scoped RRP on share routes.
  if (path === "/api/mounts" && method === "POST") return true;
  // Settings read (session-only, no RRP needed for startup)
  if (path === "/api/settings" && method === "GET") return true;
  if (path.startsWith("/api/public/")) return true;
  if (path.startsWith("/api/shares/")) return true;
  return false;
}
export const RRP_DEVICE_OVERRIDE_HEADER = "X-RefMD-RRP-Override-Device-Id";
export type RrpActorVariant = "user_device" | "share_participant_device";

export function currentRrpActorVariant(): RrpActorVariant {
  return getPreferredSessionScope() === "share" ? "share_participant_device" : "user_device";
}

type RrpHeaderParams = {
  "x-refmd-rrp-actor-variant": RrpActorVariant;
  "x-refmd-rrp-device-id": string;
  "x-refmd-rrp-challenge": string;
  "x-refmd-rrp-signature-transport": string;
};

type UserRrpHeaderParams = Omit<RrpHeaderParams, "x-refmd-rrp-actor-variant"> & {
  "x-refmd-rrp-actor-variant": "user_device";
};

function emptyRrpHeaderParams(actorVariant: RrpActorVariant): RrpHeaderParams {
  return {
    "x-refmd-rrp-actor-variant": actorVariant,
    "x-refmd-rrp-device-id": "",
    "x-refmd-rrp-challenge": "",
    "x-refmd-rrp-signature-transport": "",
  };
}

export function withRrpParams(): { header: RrpHeaderParams };
export function withRrpParams<T extends Record<string, unknown>>(
  params: T,
): T & { header: RrpHeaderParams };
export function withRrpParams<T extends Record<string, unknown>>(params?: T) {
  return {
    ...params,
    header: emptyRrpHeaderParams(currentRrpActorVariant()),
  };
}

export function withUserRrpParams(): { header: UserRrpHeaderParams };
export function withUserRrpParams<T extends Record<string, unknown>>(
  params: T,
): T & { header: UserRrpHeaderParams };
export function withUserRrpParams<T extends Record<string, unknown>>(params?: T) {
  return {
    ...params,
    header: emptyRrpHeaderParams("user_device") as UserRrpHeaderParams,
  };
}

const MAX_RATE_LIMIT_RETRIES = 3;
const MAX_CONCURRENT_RRP_REQUESTS = 10;
let getDeviceId = (): string | null => null;
let activeRrpRequests = 0;
const rrpRequestWaiters: Array<() => void> = [];
function createRequestAbortError(): Error {
  const error = new Error("request_aborted");
  error.name = "AbortError";
  return error;
}
async function acquireRrpRequestSlot(signal: AbortSignal): Promise<() => void> {
  if (signal.aborted) throw createRequestAbortError();
  if (activeRrpRequests < MAX_CONCURRENT_RRP_REQUESTS) {
    activeRrpRequests++;
    return releaseRrpRequestSlot;
  }
  await new Promise<void>((resolve, reject) => {
    const grant = () => {
      signal.removeEventListener("abort", onAbort);
      activeRrpRequests++;
      resolve();
    };
    const onAbort = () => {
      const index = rrpRequestWaiters.indexOf(grant);
      if (index >= 0) rrpRequestWaiters.splice(index, 1);
      reject(createRequestAbortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    rrpRequestWaiters.push(grant);
  });
  return releaseRrpRequestSlot;
}
function releaseRrpRequestSlot(): void {
  activeRrpRequests = Math.max(0, activeRrpRequests - 1);
  const next = rrpRequestWaiters.shift();
  if (next) next();
}
async function applyRrpHeaders(request: Request): Promise<void> {
  if (isSessionOnlyEndpoint(request.url, request.method)) return;
  const deviceIdOverride = request.headers.get(RRP_DEVICE_OVERRIDE_HEADER) ?? undefined;
  if (deviceIdOverride) {
    request.headers.delete(RRP_DEVICE_OVERRIDE_HEADER);
  }
  const deviceId = deviceIdOverride ?? getDeviceId();
  if (!deviceId) return;
  const { getRrpHeaders } = await import("@/shared/lib/auth/rrp");
  const url = new URL(request.url);
  const canonicalQuery = canonicalQueryString(url.search);
  const bodyHash = blake3Base64Url(new Uint8Array(await request.clone().arrayBuffer()));
  const headers = await getRrpHeaders(
    deviceIdOverride,
    request.signal,
    getRequestSessionScope(request),
    undefined,
    {
      body_hash: bodyHash,
      canonical_query: canonicalQuery,
      method: request.method.toUpperCase(),
      path: url.pathname,
      query_hash: blake3Base64Url(new TextEncoder().encode(canonicalQuery)),
    },
  );
  request.headers.set("X-RefMD-RRP-Device-Id", headers["X-RefMD-RRP-Device-Id"]);
  request.headers.set("X-RefMD-RRP-Actor-Variant", headers["X-RefMD-RRP-Actor-Variant"]);
  request.headers.set("X-RefMD-RRP-Challenge", headers["X-RefMD-RRP-Challenge"]);
  request.headers.set(
    "X-RefMD-RRP-Signature-Transport",
    headers["X-RefMD-RRP-Signature-Transport"],
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
// Global rate limit state: all requests wait until this timestamp passes
let rateLimitedUntil = 0;
function setGlobalRateLimit(retryAfterMs: number): void {
  const until = Date.now() + retryAfterMs;
  if (until > rateLimitedUntil) {
    rateLimitedUntil = until;
  }
  recordAuthTransportRateLimit(retryAfterMs);
}
export async function waitForGlobalRateLimit(): Promise<void> {
  while (true) {
    const remaining = rateLimitedUntil - Date.now();
    if (remaining <= 0) break;
    await sleep(remaining + Math.random() * 200);
  }
}
function parseRetryAfter(response: Response, attempt: number): number {
  const header = response.headers.get("retry-after");
  if (header) {
    const seconds = parseInt(header, 10);
    if (!isNaN(seconds) && seconds > 0) return seconds * 1000;
  }
  return Math.min(1000 * 2 ** attempt, 4000);
}

export function isPasswordChallengeEndpoint(path: string): boolean {
  return (
    /^\/api\/shares\/[^/]+\/challenge$/.test(path) || /^\/api\/mounts\/[^/]+\/challenge$/.test(path)
  );
}

export function shouldUseShareSessionScopeHeader(path: string): boolean {
  return (
    path === "/api/auth/ws-token" ||
    /^\/api\/shares\/[^/]+$/.test(path) ||
    /^\/api\/shares\/[^/]+\/bootstrap$/.test(path) ||
    /^\/api\/shares\/[^/]+\/challenge$/.test(path) ||
    /^\/api\/shares\/d\/[^/]+$/.test(path) ||
    /^\/api\/shares\/d\/[^/]+\/bootstrap$/.test(path) ||
    /^\/api\/shares\/f\/[^/]+$/.test(path) ||
    /^\/api\/shares\/f\/[^/]+\/bootstrap$/.test(path)
  );
}

function applySessionScopeHeader(request: Request): void {
  if (request.headers.has(SHARE_SESSION_SCOPE_HEADER)) return;
  if (getPreferredSessionScope() !== "share") return;

  const path = new URL(request.url, "http://localhost").pathname;
  if (shouldUseShareSessionScopeHeader(path)) {
    request.headers.set(SHARE_SESSION_SCOPE_HEADER, "share");
  }
}

function getRequestSessionScope(request: Request): AuthSessionScope {
  return request.headers.get(SHARE_SESSION_SCOPE_HEADER) === "share" ? "share" : "user";
}

function handleUnauthorizedResponse(request: Request, response: Response): void {
  if (response.status === 401) {
    notifyAuthUnauthorized(getRequestSessionScope(request));
  }
}

function createRateLimitedResponse(retryMs: number): Response {
  const retrySeconds = Math.max(1, Math.ceil(retryMs / 1000));
  return new Response(JSON.stringify({ error: "rate_limit_exceeded", retry_after: retrySeconds }), {
    status: 429,
    headers: {
      "Content-Type": "application/json",
      "Retry-After": String(retrySeconds),
    },
  });
}
function getRrpChallengeRetryMs(error: unknown): number | null {
  if (!(error instanceof RrpChallengeRateLimitError)) {
    return null;
  }
  return Math.max(1, error.retryAfterSeconds) * 1000;
}

async function createReplayableRequestFactory(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<() => Request> {
  const source = new Request(input, init);
  const headers = Array.from(source.headers.entries());
  const canHaveBody = !["GET", "HEAD"].includes(source.method.toUpperCase());
  const body = canHaveBody ? await source.clone().arrayBuffer() : undefined;

  return () =>
    new Request(source.url, {
      method: source.method,
      headers: new Headers(headers),
      body: body && body.byteLength > 0 ? body.slice(0) : undefined,
      cache: source.cache,
      credentials: source.credentials,
      integrity: source.integrity,
      keepalive: source.keepalive,
      mode: source.mode,
      redirect: source.redirect,
      referrer: source.referrer,
      referrerPolicy: source.referrerPolicy,
      signal: source.signal,
    });
}

export function initializeApiClient(config: {
  getDeviceId: () => string | null;
  onUnauthorized?: (scope: AuthSessionScope) => void;
}): void {
  getDeviceId = config.getDeviceId;
  setAuthUnauthorizedHandler(config.onUnauthorized ?? null);
}
export const client = createClient<paths>({
  baseUrl: "/",
  credentials: "include",
  fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const createRequest = await createReplayableRequestFactory(input, init);
    let lastResponse: Response | null = null;
    for (let attempt = 0; attempt <= MAX_RATE_LIMIT_RETRIES; attempt++) {
      await waitForAuthTransport();
      await waitForGlobalRateLimit();
      const request = createRequest();
      const requiresRrp = !isSessionOnlyEndpoint(request.url, request.method);
      let releaseRrpSlot: (() => void) | null = null;
      try {
        applySessionScopeHeader(request);
        if (requiresRrp) {
          releaseRrpSlot = await acquireRrpRequestSlot(request.signal);
        }
        await applyRrpHeaders(request);
        let response: Response;
        try {
          response = await fetch(request);
          clearAuthTransportNetworkFailure();
        } catch (fetchError) {
          if (fetchError instanceof Error && fetchError.name === "AbortError") {
            throw fetchError;
          }
          recordAuthTransportNetworkFailure();
          throw new ApiNetworkError(fetchError);
        }
        handleUnauthorizedResponse(request, response);
        const path = new URL(request.url, "http://localhost").pathname;
        if (response.status !== 429 || isPasswordChallengeEndpoint(path)) {
          return response;
        }
        const retryMs = parseRetryAfter(response, attempt);
        setGlobalRateLimit(retryMs);
        lastResponse = response;
      } catch (e) {
        if (e instanceof CryptoWorkerError && e.code === "rate_limited") {
          return createRateLimitedResponse(60000);
        }
        const retryMs = getRrpChallengeRetryMs(e);
        if (retryMs !== null) {
          setGlobalRateLimit(retryMs);
          const response = createRateLimitedResponse(retryMs);
          lastResponse = response;
          continue;
        }
        if (isAuthUnauthorizedError(e)) {
          notifyAuthUnauthorized(e.scope);
          throw e;
        }
        if (e instanceof Error && e.name === "AbortError") {
          throw e;
        }
        if (e instanceof ApiNetworkError) {
          throw e.cause;
        }
        if (e instanceof TypeError) {
          throw e;
        }
        clientError("rrp_headers_apply_failed", { error: e });
        throw e;
      } finally {
        releaseRrpSlot?.();
      }
    }
    return lastResponse!;
  },
});
export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;
  code: string | null;
  constructor(status: number, body: Record<string, unknown>) {
    super(`API error ${status}: ${JSON.stringify(body)}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    const code = body.code;
    const error = body.error;
    this.code =
      typeof code === "string" && code.length > 0
        ? code
        : typeof error === "string" && error.length > 0
          ? error
          : null;
  }
}
class ApiNetworkError extends Error {
  override readonly cause: unknown;

  constructor(cause: unknown) {
    super("API network request failed");
    this.name = "ApiNetworkError";
    this.cause = cause;
  }
}
export function getRateLimitRetryMs(error: unknown): number | null {
  if (!(error instanceof ApiError) || error.status !== 429) return null;
  const retryAfter = error.body?.retry_after;
  if (typeof retryAfter === "number" && retryAfter > 0) {
    return retryAfter * 1000;
  }
  if (typeof retryAfter === "string") {
    const parsed = parseFloat(retryAfter);
    if (!Number.isNaN(parsed) && parsed > 0) {
      return parsed * 1000;
    }
  }
  return 1000;
}
function throwIfError<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.error !== undefined) {
    throw new ApiError(result.response.status, result.error as Record<string, unknown>);
  }
  return result.data as T;
}
export { throwIfError };
