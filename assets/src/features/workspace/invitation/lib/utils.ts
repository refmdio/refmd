export function buildInvitationExpiryIso(expiryDays: number, nowMs = Date.now()): string {
  return new Date(nowMs + expiryDays * 24 * 60 * 60 * 1000).toISOString();
}

export function buildInvitationLink(origin: string, token: string): string {
  return `${origin}/invite#token=${token}`;
}
