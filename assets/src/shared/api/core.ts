import createClient from "openapi-fetch";
import type { paths } from "./schema";
import { getCryptoWorker, CryptoWorkerError } from "@/shared/lib/crypto/worker/client";
import { PopChallengeRateLimitError } from "@/shared/lib/auth/pop";
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

function isSessionOnlyEndpoint(url: string, method: string): boolean {
  const path = new URL(url, "http://localhost").pathname;
  // Auth: session-only subset (excludes PATCH /auth/password, PUT /auth/recovery-key)
  if (
    path === "/api/auth/me" ||
    path === "/api/auth/logout" ||
    path === "/api/auth/verify-key" ||
    path === "/api/auth/pop-challenge" ||
    path === "/api/auth/ws-token" ||
    path === "/api/auth/kdf-migration" ||
    path === "/api/auth/recovery" ||
    path === "/api/auth/password-set" ||
    path === "/api/auth/salt" ||
    path === "/api/auth/login" ||
    path === "/api/auth/register"
  ) {
    return true;
  }
  // Device: bootstrap
  if (path === "/api/devices/bootstrap") return true;
  // Device: registration endpoints (session-only), EXCEPT POST .../approve (Recovery-or-PoP)
  if (path.startsWith("/api/devices/registrations")) {
    if (method === "POST" && path.endsWith("/approve")) return false;
    return true;
  }
  // Trust transfer: nonce (POST), state retrieval (GET)
  if (path === "/api/trust-transfer/nonce") return true;
  if (path === "/api/trust-transfer/state" && method === "GET") return true;
  // Encryption setup (initial, before PoP is possible)
  if (path === "/api/encryption/setup-complete") return true;
  // Workspace creation (session-only, no PoP)
  if (path === "/api/workspaces" && method === "POST") return true;
  // Invitation lookup is unauthenticated and only resolves the token kind.
  if (path === "/api/workspaces/invitations/lookup" && method === "POST") return true;
  // Guest invitation redemption creates the guest principal/device, so PoP is impossible before it.
  if (path === "/api/workspaces/guest-invitations/redeem" && method === "POST") return true;
  // Share mount creation is user-session scoped; do not issue share-scoped PoP on share routes.
  if (path === "/api/mounts" && method === "POST") return true;
  // Settings read (session-only, no PoP needed for startup)
  if (path === "/api/settings" && method === "GET") return true;
  if (path.startsWith("/api/public/")) return true;
  if (path.startsWith("/api/shares/")) return true;
  return false;
}
export const POP_DEVICE_OVERRIDE_HEADER = "X-Pop-Override-Device-Id";
const MAX_RATE_LIMIT_RETRIES = 3;
const MAX_CONCURRENT_POP_REQUESTS = 10;
let getDeviceId = (): string | null => null;
let activePopRequests = 0;
const popRequestWaiters: Array<() => void> = [];
function createRequestAbortError(): Error {
  const error = new Error("request_aborted");
  error.name = "AbortError";
  return error;
}
async function acquirePopRequestSlot(signal: AbortSignal): Promise<() => void> {
  if (signal.aborted) throw createRequestAbortError();
  if (activePopRequests < MAX_CONCURRENT_POP_REQUESTS) {
    activePopRequests++;
    return releasePopRequestSlot;
  }
  await new Promise<void>((resolve, reject) => {
    const grant = () => {
      signal.removeEventListener("abort", onAbort);
      activePopRequests++;
      resolve();
    };
    const onAbort = () => {
      const index = popRequestWaiters.indexOf(grant);
      if (index >= 0) popRequestWaiters.splice(index, 1);
      reject(createRequestAbortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    popRequestWaiters.push(grant);
  });
  return releasePopRequestSlot;
}
function releasePopRequestSlot(): void {
  activePopRequests = Math.max(0, activePopRequests - 1);
  const next = popRequestWaiters.shift();
  if (next) next();
}
async function applyPopHeaders(request: Request): Promise<void> {
  if (isSessionOnlyEndpoint(request.url, request.method)) return;
  const deviceIdOverride = request.headers.get(POP_DEVICE_OVERRIDE_HEADER) ?? undefined;
  if (deviceIdOverride) {
    request.headers.delete(POP_DEVICE_OVERRIDE_HEADER);
  }
  const deviceId = deviceIdOverride ?? getDeviceId();
  if (!deviceId) return;
  if (!deviceIdOverride) {
    try {
      const workerReady = await getCryptoWorker().isReady();
      if (!workerReady) return;
    } catch {
      return;
    }
  }
  const { getPopHeaders } = await import("@/shared/lib/auth/pop");
  const headers = await getPopHeaders(
    deviceIdOverride,
    request.signal,
    getRequestSessionScope(request),
  );
  request.headers.set("X-PoP-Device-Id", headers["X-PoP-Device-Id"]);
  request.headers.set("X-PoP-Challenge", headers["X-PoP-Challenge"]);
  request.headers.set("X-PoP-Signature", headers["X-PoP-Signature"]);
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
    /^\/api\/shares\/f\/[^/]+$/.test(path)
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
function getPopChallengeRetryMs(error: unknown): number | null {
  if (!(error instanceof PopChallengeRateLimitError)) {
    return null;
  }
  return Math.max(1, error.retryAfterSeconds) * 1000;
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
    let lastResponse: Response | null = null;
    for (let attempt = 0; attempt <= MAX_RATE_LIMIT_RETRIES; attempt++) {
      await waitForAuthTransport();
      await waitForGlobalRateLimit();
      const request = new Request(input, init);
      const requiresPop = !isSessionOnlyEndpoint(request.url, request.method);
      let releasePopSlot: (() => void) | null = null;
      try {
        applySessionScopeHeader(request);
        if (requiresPop) {
          releasePopSlot = await acquirePopRequestSlot(request.signal);
        }
        await applyPopHeaders(request);
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
        const retryMs = getPopChallengeRetryMs(e);
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
        console.error("[PoP] Failed to apply PoP headers:", e);
        throw e;
      } finally {
        releasePopSlot?.();
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
