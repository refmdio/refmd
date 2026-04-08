const TOKEN_SESSION_KEY = "refmd_invite_token";

export function readInvitationToken(): string | null {
  const hash = window.location.hash;
  if (hash.startsWith("#token=")) {
    const token = hash.slice("#token=".length);
    sessionStorage.setItem(TOKEN_SESSION_KEY, token);
    history.replaceState(null, "", window.location.pathname);
    return token;
  }

  return sessionStorage.getItem(TOKEN_SESSION_KEY);
}

export function getStoredInvitationToken(): string | null {
  return sessionStorage.getItem(TOKEN_SESSION_KEY);
}

export function clearInvitationToken(): void {
  sessionStorage.removeItem(TOKEN_SESSION_KEY);
}
