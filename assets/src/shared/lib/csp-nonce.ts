let cached: string | null = null;

export function getCspNonce(): string {
  if (cached !== null) return cached;
  cached = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? "";
  return cached;
}
