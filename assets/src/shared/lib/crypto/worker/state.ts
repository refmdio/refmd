// Worker-internal key state. This module runs ONLY inside the Crypto Worker.
// Keys stored here never leave the worker context.

export interface WorkerKeyState {
  initialized: boolean;
  userId: string | null;
  deviceId: string | null;

  // DSK (Web Crypto API non-exportable CryptoKey)
  dsk: CryptoKey | null;

  // UMK (32 bytes)
  umk: Uint8Array | null;

  // Identity key pairs
  identityEcdhPrivate: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
  identitySigningPrivate: Uint8Array | null;
  identitySigningPublic: Uint8Array | null;

  // Device key pairs
  deviceEcdhPrivate: Uint8Array | null;
  deviceEcdhPublic: Uint8Array | null;
  deviceSigningPrivate: Uint8Array | null;
  deviceSigningPublic: Uint8Array | null;

  // KEK cache: workspaceId -> keyVersion -> { kek, resolvedAt }
  kekCache: Map<string, Map<number, { kek: Uint8Array; resolvedAt: number }>>;

  // Active KEK version per workspace (set by resolveActiveKek, authoritative source)
  activeKekVersions: Map<string, number>;

  // DEK cache: documentId -> keyVersion -> dek
  dekCache: Map<string, Map<number, Uint8Array>>;

  // Active DEK version per document
  activeDekVersions: Map<string, number>;
}

const KEK_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export function createInitialState(): WorkerKeyState {
  return {
    initialized: false,
    userId: null,
    deviceId: null,
    dsk: null,
    umk: null,
    identityEcdhPrivate: null,
    identityEcdhPublic: null,
    identitySigningPrivate: null,
    identitySigningPublic: null,
    deviceEcdhPrivate: null,
    deviceEcdhPublic: null,
    deviceSigningPrivate: null,
    deviceSigningPublic: null,
    kekCache: new Map(),
    activeKekVersions: new Map(),
    dekCache: new Map(),
    activeDekVersions: new Map(),
  };
}

export function clearState(state: WorkerKeyState): void {
  state.initialized = false;
  state.userId = null;
  state.deviceId = null;
  state.dsk = null;

  // Overwrite sensitive key material before nulling
  zeroOut(state.umk);
  state.umk = null;

  zeroOut(state.identityEcdhPrivate);
  state.identityEcdhPrivate = null;
  state.identityEcdhPublic = null;
  zeroOut(state.identitySigningPrivate);
  state.identitySigningPrivate = null;
  state.identitySigningPublic = null;

  zeroOut(state.deviceEcdhPrivate);
  state.deviceEcdhPrivate = null;
  state.deviceEcdhPublic = null;
  zeroOut(state.deviceSigningPrivate);
  state.deviceSigningPrivate = null;
  state.deviceSigningPublic = null;

  for (const versionMap of state.kekCache.values()) {
    for (const entry of versionMap.values()) {
      zeroOut(entry.kek);
    }
  }
  state.kekCache.clear();
  state.activeKekVersions.clear();

  for (const versionMap of state.dekCache.values()) {
    for (const dek of versionMap.values()) {
      zeroOut(dek);
    }
  }
  state.dekCache.clear();
  state.activeDekVersions.clear();
}

// ── KEK cache helpers ─────────────────────────────────────

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

  // No specific version requested: return the explicitly tracked active version
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

  // Auto-set active version if none is tracked yet for this workspace
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

// ── DEK cache helpers ─────────────────────────────────────

export function getCachedDek(
  state: WorkerKeyState,
  documentId: string,
  keyVersion?: number,
): { dek: Uint8Array; keyVersion: number } | null {
  const versionMap = state.dekCache.get(documentId);
  if (!versionMap) return null;

  if (keyVersion !== undefined) {
    const dek = versionMap.get(keyVersion);
    if (!dek) return null;
    return { dek, keyVersion };
  }

  // No specific version: return active version
  const activeVersion = state.activeDekVersions.get(documentId);
  if (activeVersion !== undefined) {
    const dek = versionMap.get(activeVersion);
    if (dek) return { dek, keyVersion: activeVersion };
  }
  return null;
}

export function setCachedDek(
  state: WorkerKeyState,
  documentId: string,
  dek: Uint8Array,
  keyVersion: number,
): void {
  let versionMap = state.dekCache.get(documentId);
  if (!versionMap) {
    versionMap = new Map();
    state.dekCache.set(documentId, versionMap);
  }
  const existing = versionMap.get(keyVersion);
  if (existing) {
    zeroOut(existing);
  }
  versionMap.set(keyVersion, dek);
}

export function evictCachedDek(
  state: WorkerKeyState,
  documentId: string,
  keyVersion: number,
): void {
  const versionMap = state.dekCache.get(documentId);
  if (!versionMap) return;
  const existing = versionMap.get(keyVersion);
  if (existing) {
    zeroOut(existing);
    versionMap.delete(keyVersion);
  }
}

export function setActiveDekVersion(
  state: WorkerKeyState,
  documentId: string,
  keyVersion: number,
): void {
  state.activeDekVersions.set(documentId, keyVersion);
}

// ── Utility ───────────────────────────────────────────────

function zeroOut(arr: Uint8Array | null): void {
  if (arr) {
    arr.fill(0);
  }
}
