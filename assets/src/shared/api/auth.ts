import { client, throwIfError } from "./core";
import type { components } from "./schema";
import { SHARE_SESSION_SCOPE_HEADER } from "@/shared/lib/auth/session-scope";

type RegisterRequest = components["schemas"]["RegisterRequest"];
type LoginRequest = components["schemas"]["LoginRequest"];

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

  logout: async (options?: { sessionScope?: "share" }) =>
    throwIfError(
      await client.POST("/api/auth/logout", {
        headers:
          options?.sessionScope === "share" ? { [SHARE_SESSION_SCOPE_HEADER]: "share" } : undefined,
      }),
    ),

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

  wsToken: async (options?: { sessionScope?: "user" | "share" }): Promise<{ token: string }> =>
    throwIfError(
      await client.POST("/api/auth/ws-token", {
        headers: options?.sessionScope
          ? { [SHARE_SESSION_SCOPE_HEADER]: options.sessionScope }
          : undefined,
      }),
    ),
};
