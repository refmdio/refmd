const INVITE_LOOKUP_TOKEN_KEY = "refmd_invite_lookup_token";

export function resolvePostAuthRedirect(fallback: string): string {
  return sessionStorage.getItem(INVITE_LOOKUP_TOKEN_KEY) ? "/invite" : fallback;
}
