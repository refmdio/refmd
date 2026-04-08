const INVITE_TOKEN_KEY = "refmd_invite_token";

export function resolvePostAuthRedirect(fallback: string): string {
  return sessionStorage.getItem(INVITE_TOKEN_KEY) ? "/invite" : fallback;
}
