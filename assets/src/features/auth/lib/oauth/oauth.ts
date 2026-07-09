import { ApiError, authApi, type OAuthProvider } from "@/shared/api";

export type { OAuthProvider };

export async function loadOAuthProviders(): Promise<OAuthProvider[]> {
  const response = await authApi.oauthProviders();
  return response.providers;
}

export async function startOAuthAuthorization(
  provider: OAuthProvider,
  returnTo: string,
): Promise<void> {
  try {
    const response = await authApi.oauthStart(provider, { return_to: returnTo });
    window.location.assign(response.authorization_url);
  } catch (error) {
    throw new Error(oauthStartErrorMessage(error, provider));
  }
}

function oauthStartErrorMessage(error: unknown, provider: OAuthProvider): string {
  if (error instanceof ApiError) {
    const details = isRecord(error.body.details) ? error.body.details : null;

    if (error.code === "oauth_provider_not_configured" && details) {
      const missing = typeof details.missing === "string" ? details.missing : "required setting";
      return `${providerLabel(provider)} OAuth is not configured: ${missing} is missing.`;
    }

    if (error.code === "oauth_token_exchange_failed" && details) {
      const providerError = isRecord(details.provider_error) ? details.provider_error : null;
      const providerCode =
        providerError && typeof providerError.error === "string" ? providerError.error : null;
      const description =
        providerError && typeof providerError.error_description === "string"
          ? providerError.error_description
          : null;

      if (providerCode && description) {
        return `${providerLabel(provider)} OAuth token exchange failed: ${providerCode}: ${description}`;
      }
      if (providerCode) {
        return `${providerLabel(provider)} OAuth token exchange failed: ${providerCode}.`;
      }
    }
  }

  return error instanceof Error
    ? error.message
    : `${providerLabel(provider)} OAuth sign in failed.`;
}

function providerLabel(provider: OAuthProvider): string {
  return provider === "google" ? "Google" : "GitHub";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
