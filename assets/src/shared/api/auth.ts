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
      await client.DELETE("/api/auth/session"),
    ),

  kdfMigration: async (body: components["schemas"]["KdfMigrationRequest"]) =>
    throwIfError(
      await client.POST("/api/auth/kdf-migration", { body }),
    ),
};
