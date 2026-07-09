import { describe, expect, it, vi } from "vite-plus/test";

const { oauthProviders, oauthStart } = vi.hoisted(() => ({
  oauthProviders: vi.fn(),
  oauthStart: vi.fn(),
}));

vi.mock("@/shared/api", () => {
  class ApiError extends Error {
    status: number;
    body: Record<string, unknown>;
    code: string | null;

    constructor(status: number, body: Record<string, unknown>) {
      super(`API error ${status}: ${JSON.stringify(body)}`);
      this.status = status;
      this.body = body;
      this.code = typeof body.error === "string" ? body.error : null;
    }
  }

  return {
    ApiError,
    authApi: {
      oauthProviders,
      oauthStart,
    },
  };
});

import { ApiError } from "@/shared/api";
import { loadOAuthProviders, startOAuthAuthorization } from "./oauth";

describe("startOAuthAuthorization", () => {
  it("loads enabled OAuth providers", async () => {
    oauthProviders.mockResolvedValueOnce({ providers: ["google"] });

    await expect(loadOAuthProviders()).resolves.toEqual(["google"]);
  });

  it("surfaces missing provider configuration details", async () => {
    oauthStart.mockRejectedValueOnce(
      new ApiError(422, {
        error: "oauth_provider_not_configured",
        details: { provider: "google", missing: "client_secret" },
      }),
    );

    await expect(startOAuthAuthorization("google", "/dashboard")).rejects.toThrow(
      "Google OAuth is not configured: client_secret is missing.",
    );
  });

  it("surfaces safe token exchange provider errors", async () => {
    oauthStart.mockRejectedValueOnce(
      new ApiError(401, {
        error: "oauth_token_exchange_failed",
        details: {
          provider: "google",
          provider_error: {
            error: "invalid_request",
            error_description: "client_secret is missing.",
          },
        },
      }),
    );

    await expect(startOAuthAuthorization("google", "/dashboard")).rejects.toThrow(
      "Google OAuth token exchange failed: invalid_request: client_secret is missing.",
    );
  });
});
