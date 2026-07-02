import { prewarmShareParticipantKeypair } from "./keypair-prewarm";

function shareSlugFromLandingPath(pathname = window.location.pathname): string | null {
  const match = /^\/share\/([A-Za-z0-9_-]{22})\/?$/.exec(pathname);
  return match?.[1] ?? null;
}

function hasDirectShareBootstrapMaterial(hash = window.location.hash): boolean {
  const normalized = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!normalized) return false;
  const params = new URLSearchParams(normalized);
  return (
    /^[A-Za-z0-9_-]{43}$/.test(params.get("cap") ?? "") &&
    /^[A-Za-z0-9_-]{43}$/.test(params.get("wpb") ?? "")
  );
}

export function prewarmShareLandingPath(): void {
  const shareSlug = shareSlugFromLandingPath();
  if (!shareSlug || !hasDirectShareBootstrapMaterial()) return;

  prewarmShareParticipantKeypair(shareSlug);
}
