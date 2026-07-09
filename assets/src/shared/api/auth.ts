import { client, throwIfError, withUserRrpParams } from "./core";
import type { components } from "./schema";
import { SHARE_SESSION_SCOPE_HEADER } from "@/shared/lib/auth/session-scope";

type RegisterRequest = components["schemas"]["RegisterRequest"];
type LoginRequest = components["schemas"]["LoginRequest"];
type RecoverySessionRequest = components["schemas"]["RecoverySessionRequest"];
type OAuthStartRequest = components["schemas"]["OAuthStartRequest"];
type OAuthCryptoSetupRequest = components["schemas"]["OAuthCryptoSetupRequest"];
type PasswordSetRequest = components["schemas"]["PasswordSetRequest"];
export type OAuthProvider = "google" | "github";
export type ExternalAccountsResponse = components["schemas"]["ExternalAccountsResponse"];

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

  oauthProviders: async () => throwIfError(await client.GET("/api/auth/oauth/providers")),

  oauthStart: async (provider: OAuthProvider, body: OAuthStartRequest) =>
    throwIfError(
      await client.POST("/api/auth/oauth/{provider}/start", {
        params: { path: { provider } },
        body,
      }),
    ),

  oauthLinkStart: async (provider: OAuthProvider, body: OAuthStartRequest) =>
    throwIfError(
      await client.POST("/api/auth/oauth/{provider}/link/start", {
        params: withUserRrpParams({ path: { provider } }),
        body,
      }),
    ),

  oauthCryptoSetup: async (body: OAuthCryptoSetupRequest) =>
    throwIfError(await client.POST("/api/auth/oauth/crypto-setup", { body })),

  me: async () => throwIfError(await client.GET("/api/auth/me")),

  externalAccounts: async (): Promise<ExternalAccountsResponse> =>
    throwIfError(await client.GET("/api/auth/external-accounts")),

  unlinkExternalAccount: async (provider: OAuthProvider) =>
    throwIfError(
      await client.DELETE("/api/auth/external-accounts/{provider}", {
        params: withUserRrpParams({ path: { provider } }),
      }),
    ),

  logout: async (options?: { clearMountSession?: boolean; sessionScope?: "share" }) =>
    throwIfError(
      await client.POST("/api/auth/logout", {
        body: { clear_mount_session: options?.clearMountSession === true },
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

  recoverySession: async (body: RecoverySessionRequest) =>
    throwIfError(
      await client.POST("/api/auth/recovery/session", {
        body,
      }),
    ),

  passwordSet: async (body: {
    new_auth_key: string;
    new_salt: string;
    new_encrypted_umk: string;
    new_umk_nonce: string;
  }) => throwIfError(await client.POST("/api/auth/password-set", { body })),

  passwordSetup: async (body: PasswordSetRequest) =>
    throwIfError(
      await client.POST("/api/auth/password/setup", {
        params: withUserRrpParams(),
        body,
      }),
    ),

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
        headers:
          options?.sessionScope === "share" ? { [SHARE_SESSION_SCOPE_HEADER]: "share" } : undefined,
      }),
    ),
};
