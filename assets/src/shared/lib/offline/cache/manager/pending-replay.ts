import type { DocumentCacheEntry } from "@/shared/lib/offline/storage/store";

type PendingReplayCacheEntry = Pick<
  DocumentCacheEntry,
  "encryptedStateKind" | "encryptedConfirmedState" | "confirmedStateNonce"
>;

export function shouldReplayCachedPendingChanges(
  cacheEntry: PendingReplayCacheEntry | null,
  hasConfirmedBaseState: boolean,
): boolean {
  if (!cacheEntry) return false;
  if (cacheEntry.encryptedStateKind === "live") return false;
  if (cacheEntry.encryptedStateKind === "confirmed") return true;
  if (hasConfirmedBaseState) return true;
  return Boolean(cacheEntry.encryptedConfirmedState && cacheEntry.confirmedStateNonce);
}

export function shouldTreatCachedStateAsConfirmedBase(
  cacheEntry: PendingReplayCacheEntry,
  hasConfirmedBaseState: boolean,
  hasPendingCandidate: boolean,
): boolean {
  if (hasConfirmedBaseState) return true;
  if (cacheEntry.encryptedStateKind === "confirmed") return true;
  if (cacheEntry.encryptedStateKind === "live") return false;
  return !hasPendingCandidate;
}
