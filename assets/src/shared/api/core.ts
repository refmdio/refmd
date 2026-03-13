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

export const client = createClient<paths>({
  baseUrl: "/",
  credentials: "include",
});

client.use({
  async onRequest({ request }) {
    const override = popDeviceOverride;
    const state = deviceState();
    const deviceId = override?.deviceId ?? state?.deviceId;
    const signingPrivate = override?.deviceSigningPrivate ?? state?.deviceSigningPrivate;

    if (!deviceId || !signingPrivate) {
      return undefined;
    }

    if (isSessionOnlyEndpoint(request.url, request.method)) {
      return undefined;
    }

    try {
      const headers = await getPopHeaders(override ?? undefined);
      request.headers.set("X-PoP-Device-Id", headers["X-PoP-Device-Id"]);
      request.headers.set("X-PoP-Challenge", headers["X-PoP-Challenge"]);
      request.headers.set("X-PoP-Signature", headers["X-PoP-Signature"]);
    } catch {
      // Continue without PoP — server will reject if required
    }
    return undefined;
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
