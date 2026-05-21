export function buildInvitationExpiryIso(expiryDays: number, nowMs = Date.now()): string {
  return new Date(nowMs + expiryDays * 24 * 60 * 60 * 1000).toISOString();
}

export function buildInvitationLink(origin: string, token: string): string {
  const [lookupToken, bootstrapSecret] = token.split(".");
  const params = new URLSearchParams({ it: lookupToken, ib: bootstrapSecret });
  return `${origin}/invite#${params.toString()}`;
}
