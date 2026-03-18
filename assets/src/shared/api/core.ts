import createClient from "openapi-fetch";
import type { paths } from "./schema";
import type { ExplicitDeviceKeys } from "@/shared/lib/pop";
import { getPopHeaders } from "@/shared/lib/pop";
import { deviceState } from "@/shared/lib/auth-state";

function isSessionOnlyEndpoint(url: string, method: string): boolean {
  const path = new URL(url, "http://localhost").pathname;

  // Auth: session-only subset (excludes PATCH /auth/password, PUT /auth/recovery-key)
  if (
    path === "/api/auth/me" ||
    path === "/api/auth/logout" ||
    path === "/api/auth/verify-key" ||
    path === "/api/auth/pop-challenge" ||
    path === "/api/auth/kdf-migration" ||
    path === "/api/auth/recovery" ||
    path === "/api/auth/password-set"
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

  // Device events SSE
  if (path === "/api/devices/events") return true;

  // Trust transfer: nonce (POST), state retrieval (GET)
  if (path === "/api/trust-transfer/nonce") return true;
  if (path === "/api/trust-transfer/state" && method === "GET") return true;

  // Encryption setup (initial, before PoP is possible)
  if (path === "/api/encryption/setup-complete") return true;

  // Workspace creation (session-only, no PoP)
  if (path === "/api/workspaces" && method === "POST") return true;

  // Settings read (session-only, no PoP needed for startup)
  if (path === "/api/settings" && method === "GET") return true;

  return false;
}

let popDeviceOverride: ExplicitDeviceKeys | null = null;

export async function withPopDevice<T>(
  device: ExplicitDeviceKeys,
  fn: () => Promise<T>,
): Promise<T> {
  popDeviceOverride = device;
  try {
    return await fn();
  } finally {
    popDeviceOverride = null;
  }
}

const MAX_RATE_LIMIT_RETRIES = 3;

async function applyPopHeaders(request: Request): Promise<void> {
  const override = popDeviceOverride;
  const state = deviceState();
  const deviceId = override?.deviceId ?? state?.deviceId;
  const signingPrivate = override?.deviceSigningPrivate ?? state?.deviceSigningPrivate;

  if (!deviceId || !signingPrivate) return;
  if (isSessionOnlyEndpoint(request.url, request.method)) return;

  const headers = await getPopHeaders(override ?? undefined);
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

export function handleRateLimitResponse(response: Response, attempt: number): void {
  const retryMs = parseRetryAfter(response, attempt);
  setGlobalRateLimit(retryMs);
}

export const client = createClient<paths>({
  baseUrl: "/",
  credentials: "include",
  fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    let lastResponse: Response | null = null;

    for (let attempt = 0; attempt <= MAX_RATE_LIMIT_RETRIES; attempt++) {
      await waitForGlobalRateLimit();

      const request = new Request(input, init);

      try {
        await applyPopHeaders(request);
      } catch (e) {
        if (e instanceof Error && e.message.includes("rate limited")) {
          const retryAfter = (e as any).retryAfter ?? "60";
          return new Response(
            JSON.stringify({ error: "rate_limit_exceeded", retry_after: parseInt(retryAfter, 10) }),
            {
              status: 429,
              headers: { "Content-Type": "application/json", "Retry-After": retryAfter },
            },
          );
        }
        // Other errors (device not available, crypto): continue without PoP
      }

      const response = await fetch(request);

      if (response.status !== 429) {
        return response;
      }

      const retryMs = parseRetryAfter(response, attempt);
      setGlobalRateLimit(retryMs);

      if (retryMs > 10_000) {
        return response;
      }

      lastResponse = response;
    }

    return lastResponse!;
  },
});

export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown>) {
    super(`API error ${status}: ${JSON.stringify(body)}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

function throwIfError<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.error !== undefined) {
    throw new ApiError(result.response.status, result.error as Record<string, unknown>);
  }
  return result.data as T;
}

export { throwIfError };
