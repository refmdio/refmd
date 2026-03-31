import { client, throwIfError } from "./core";
import type { components } from "./schema";

export type KdfParams = components["schemas"]["KdfParams"];
export type SaltResponse = components["schemas"]["SaltResponse"];
export type RegisterRequest = components["schemas"]["RegisterRequest"];
export type RegisterResponse = components["schemas"]["RegisterResponse"];
export type LoginRequest = components["schemas"]["LoginRequest"];
export type LoginResponse = components["schemas"]["LoginResponse"];
export type LoginKeys = components["schemas"]["LoginKeys"];
export type MeResponse = components["schemas"]["MeResponse"];

export const authApi = {
  getSalt: async (email: string) =>
    throwIfError(
      await client.GET("/api/auth/salt", {
        params: { query: { email } },
      }),
    ),

  register: async (body: RegisterRequest) =>
    throwIfError(await client.POST("/api/auth/register", { body })),

  login: async (body: LoginRequest) => throwIfError(await client.POST("/api/auth/login", { body })),

  me: async () => throwIfError(await client.GET("/api/auth/me")),

  logout: async () => throwIfError(await client.POST("/api/auth/logout")),

  kdfMigration: async (body: components["schemas"]["KdfMigrationRequest"]) =>
    throwIfError(await client.POST("/api/auth/kdf-migration", { body })),

  getRecovery: async () => throwIfError(await client.GET("/api/auth/recovery")),

  recoveryChallenge: async (email: string) =>
    throwIfError(
      await client.POST("/api/auth/recovery/challenge", {
        body: { email },
      }),
    ),

  recoverySession: async (body: {
    email: string;
    challenge: string;
    signature: string;
    timestamp: number;
  }) => throwIfError(await client.POST("/api/auth/recovery/session", { body })),

  passwordSet: async (body: {
    new_auth_key: string;
    new_salt: string;
    new_encrypted_umk: string;
    new_umk_nonce: string;
  }) => throwIfError(await client.POST("/api/auth/password-set", { body })),

  verifyKey: async (authKey: string) => {
    throwIfError(
      await client.POST("/api/auth/verify-key", {
        body: { auth_key: authKey },
      }),
    );
  },

  passwordResetRequest: async (email: string) =>
    throwIfError(
      await client.POST("/api/auth/password-reset/request", {
        body: { email },
      }),
    ),

  passwordResetVerify: async (token: string) =>
    throwIfError(
      await client.POST("/api/auth/password-reset/verify", {
        body: { token },
      }),
    ),

  popChallenge: async (
    deviceId: string,
    init?: Pick<RequestInit, "signal">,
  ): Promise<{ challenge: string }> => {
    const { waitForGlobalRateLimit, handleRateLimitResponse } = await import("./core");
    let lastRetryAfter = "60";
    for (let attempt = 0; attempt <= 3; attempt++) {
      await waitForGlobalRateLimit();
      const res = await fetch("/api/auth/pop-challenge", {
        method: "POST",
        credentials: "include",
        signal: init?.signal,
        headers: {
          "Content-Type": "application/json",
          "X-PoP-Device-Id": deviceId,
        },
      });
      if (res.status === 429) {
        lastRetryAfter = res.headers.get("retry-after") ?? lastRetryAfter;
        handleRateLimitResponse(res, attempt);
        const retrySeconds = parseInt(lastRetryAfter, 10);
        if (!isNaN(retrySeconds) && retrySeconds > 10) break;
        continue;
      }
      if (!res.ok) throw new Error(`pop-challenge failed: ${res.status}`);
      return res.json();
    }
    const err = new Error("pop-challenge failed: rate limited");
    (err as any).retryAfter = lastRetryAfter;
    throw err;
  },

  wsToken: async (): Promise<{ token: string }> =>
    throwIfError(await client.POST("/api/auth/ws-token")),
};
