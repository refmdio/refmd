import { blake3Base64Url } from "@/shared/lib/crypto/hash";

const LOOKUP_TOKEN_SESSION_KEY = "refmd_invite_lookup_token";
let invitationTokenMemory: string | null = null;

export function invitationLookupToken(token: string): string {
  return token.split(".", 1)[0] ?? token;
}

export function invitationBootstrapSecret(token: string): string | null {
  const [, secret] = token.split(".");
  return secret || null;
}

export function invitationTokenWithFragmentSecrets(
  lookupToken: string,
  bootstrapSecret: string,
): string {
  return `${lookupToken}.${bootstrapSecret}`;
}

export async function invitationSecretCommitment(
  lookupToken: string,
  bootstrapSecret: string,
  purpose: "workspace" | "guest",
): Promise<string> {
  return blake3Base64Url(
    new TextEncoder().encode(
      `refmd.invitation-bootstrap-secret.${purpose}.v1:${lookupToken}:${bootstrapSecret}`,
    ),
  );
}

export function readInvitationToken(): string | null {
  const hash = window.location.hash;
  if (hash.startsWith("#")) {
    const params = new URLSearchParams(hash.slice(1));
    const lookupToken = params.get("it");
    const bootstrapSecret = params.get("ib");
    if (!lookupToken) return invitationTokenMemory;
    const token = bootstrapSecret
      ? invitationTokenWithFragmentSecrets(lookupToken, bootstrapSecret)
      : lookupToken;
    invitationTokenMemory = token;
    sessionStorage.setItem(LOOKUP_TOKEN_SESSION_KEY, lookupToken);
    history.replaceState(null, "", window.location.pathname);
    return token;
  }

  return invitationTokenMemory;
}

export function getStoredInvitationToken(): string | null {
  return invitationTokenMemory;
}

export function clearInvitationToken(): void {
  invitationTokenMemory = null;
  sessionStorage.removeItem(LOOKUP_TOKEN_SESSION_KEY);
}
