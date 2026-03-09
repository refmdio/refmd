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
    throwIfError(
      await client.POST("/api/auth/register", { body }),
    ),

  login: async (body: LoginRequest) =>
    throwIfError(
      await client.POST("/api/auth/login", { body }),
    ),

  me: async () =>
    throwIfError(
      await client.GET("/api/auth/me"),
    ),

  logout: async () =>
    throwIfError(
      await client.POST("/api/auth/logout"),
    ),

  kdfMigration: async (body: components["schemas"]["KdfMigrationRequest"]) =>
    throwIfError(
      await client.POST("/api/auth/kdf-migration", { body }),
    ),

  getRecovery: async () =>
    throwIfError(
      await client.GET("/api/auth/recovery"),
    ),

  recoveryChallenge: async (email: string): Promise<{ challenge: string }> => {
    const res = await fetch("/api/auth/recovery/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
      credentials: "include",
    });
    if (!res.ok) throw new Error("Recovery challenge failed");
    return res.json();
  },

  recoverySession: async (body: {
    email: string;
    challenge: string;
    signature: string;
    timestamp: number;
  }): Promise<{ user: { id: string; email: string; name: string }; session_id: string; is_recovery: boolean }> => {
    const res = await fetch("/api/auth/recovery/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "include",
    });
    if (!res.ok) throw new Error("Recovery session failed");
    return res.json();
  },

  passwordSet: async (body: {
    new_auth_key: string;
    new_salt: string;
    new_encrypted_umk: string;
    new_umk_nonce: string;
  }): Promise<{ ok: boolean; session_id: string }> => {
    const res = await fetch("/api/auth/password-set", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "include",
    });
    if (!res.ok) throw new Error("Password set failed");
    return res.json();
  },

  verifyKey: async (authKey: string): Promise<void> => {
    const res = await fetch("/api/auth/verify-key", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auth_key: authKey }),
      credentials: "include",
    });
    if (!res.ok) throw new Error("Invalid password");
  },

  popChallenge: async (deviceId: string): Promise<{ challenge: string }> => {
    const res = await fetch("/api/auth/pop-challenge", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-PoP-Device-Id": deviceId,
      },
    });
    if (!res.ok) throw new Error(`pop-challenge failed: ${res.status}`);
    return res.json();
  },
};
