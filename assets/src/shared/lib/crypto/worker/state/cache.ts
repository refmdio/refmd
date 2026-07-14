import type { WorkerKeyState } from "./shared";
import { zeroOut } from "./shared";

const KEK_CACHE_TTL_MS = 5 * 60 * 1000;

export function getCachedKek(
  state: WorkerKeyState,
  workspaceId: string,
  keyVersion?: number,
): { kek: Uint8Array; keyVersion: number } | null {
  const versionMap = state.kekCache.get(workspaceId);
  if (!versionMap) return null;

  if (keyVersion !== undefined) {
    const entry = versionMap.get(keyVersion);
    if (!entry) return null;
    if (Date.now() - entry.resolvedAt > KEK_CACHE_TTL_MS) {
      zeroOut(entry.kek);
      versionMap.delete(keyVersion);
      return null;
    }
    return { kek: entry.kek, keyVersion };
  }

  const activeVersion = state.activeKekVersions.get(workspaceId);
  if (activeVersion !== undefined) {
    const activeEntry = versionMap.get(activeVersion);
    if (activeEntry) {
      if (Date.now() - activeEntry.resolvedAt > KEK_CACHE_TTL_MS) {
        zeroOut(activeEntry.kek);
        versionMap.delete(activeVersion);
        return null;
      }
      return { kek: activeEntry.kek, keyVersion: activeVersion };
    }
  }

  return null;
}

export function setCachedKek(
  state: WorkerKeyState,
  workspaceId: string,
  kek: Uint8Array,
  keyVersion: number,
): void {
  let versionMap = state.kekCache.get(workspaceId);
  if (!versionMap) {
    versionMap = new Map();
    state.kekCache.set(workspaceId, versionMap);
  }

  const existing = versionMap.get(keyVersion);
  if (existing) {
    zeroOut(existing.kek);
  }
  versionMap.set(keyVersion, { kek, resolvedAt: Date.now() });

  if (!state.activeKekVersions.has(workspaceId)) {
    state.activeKekVersions.set(workspaceId, keyVersion);
  }
}

export function setActiveKekVersion(
  state: WorkerKeyState,
  workspaceId: string,
  keyVersion: number,
): void {
  state.activeKekVersions.set(workspaceId, keyVersion);
}

export function evictCachedKek(
  state: WorkerKeyState,
  workspaceId: string,
  keyVersion: number,
): boolean {
  const versionMap = state.kekCache.get(workspaceId);
  const entry = versionMap?.get(keyVersion);
  if (!versionMap || !entry) return false;

  zeroOut(entry.kek);
  versionMap.delete(keyVersion);
  if (versionMap.size === 0) {
    state.kekCache.delete(workspaceId);
  }
  return true;
}

export function getCachedDek(
  state: WorkerKeyState,
  cacheKey: string,
  keyVersion?: number,
): { dek: Uint8Array; keyVersion: number } | null {
  const versionMap = state.dekCache.get(cacheKey);
  if (!versionMap) return null;

  if (keyVersion !== undefined) {
    const dek = versionMap.get(keyVersion);
    if (!dek) return null;
    return { dek, keyVersion };
  }

  const activeVersion = state.activeDekVersions.get(cacheKey);
  if (activeVersion !== undefined) {
    const dek = versionMap.get(activeVersion);
    if (dek) return { dek, keyVersion: activeVersion };
  }

  return null;
}

export function setCachedDek(
  state: WorkerKeyState,
  cacheKey: string,
  dek: Uint8Array,
  keyVersion: number,
): void {
  let versionMap = state.dekCache.get(cacheKey);
  if (!versionMap) {
    versionMap = new Map();
    state.dekCache.set(cacheKey, versionMap);
  }

  const existing = versionMap.get(keyVersion);
  if (existing) {
    zeroOut(existing);
  }
  versionMap.set(keyVersion, dek);
}

export function evictCachedDek(state: WorkerKeyState, cacheKey: string, keyVersion: number): void {
  const versionMap = state.dekCache.get(cacheKey);
  if (!versionMap) return;

  const existing = versionMap.get(keyVersion);
  if (existing) {
    zeroOut(existing);
    versionMap.delete(keyVersion);
  }
}

export function setActiveDekVersion(
  state: WorkerKeyState,
  cacheKey: string,
  keyVersion: number,
): void {
  state.activeDekVersions.set(cacheKey, keyVersion);
}
