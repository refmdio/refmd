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

  // KEK cache: workspaceId -> { kek, keyVersion, resolvedAt }
  kekCache: Map<string, { kek: Uint8Array; keyVersion: number; resolvedAt: number }>;

  // DEK cache: documentId -> { dek, keyVersion }
  dekCache: Map<string, { dek: Uint8Array; keyVersion: number }>;
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
    dekCache: new Map(),
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

  for (const entry of state.kekCache.values()) {
    zeroOut(entry.kek);
  }
  state.kekCache.clear();

  for (const entry of state.dekCache.values()) {
    zeroOut(entry.dek);
  }
  state.dekCache.clear();
}

// ── KEK cache helpers ─────────────────────────────────────

export function getCachedKek(
  state: WorkerKeyState,
  workspaceId: string,
): { kek: Uint8Array; keyVersion: number } | null {
  const entry = state.kekCache.get(workspaceId);
  if (!entry) return null;
  if (Date.now() - entry.resolvedAt > KEK_CACHE_TTL_MS) {
    zeroOut(entry.kek);
    state.kekCache.delete(workspaceId);
    return null;
  }
  return { kek: entry.kek, keyVersion: entry.keyVersion };
}

export function setCachedKek(
  state: WorkerKeyState,
  workspaceId: string,
  kek: Uint8Array,
  keyVersion: number,
): void {
  const existing = state.kekCache.get(workspaceId);
  if (existing) {
    zeroOut(existing.kek);
  }
  state.kekCache.set(workspaceId, { kek, keyVersion, resolvedAt: Date.now() });
}

// ── DEK cache helpers ─────────────────────────────────────

export function getCachedDek(
  state: WorkerKeyState,
  documentId: string,
): { dek: Uint8Array; keyVersion: number } | null {
  return state.dekCache.get(documentId) ?? null;
}

export function setCachedDek(
  state: WorkerKeyState,
  documentId: string,
  dek: Uint8Array,
  keyVersion: number,
): void {
  const existing = state.dekCache.get(documentId);
  if (existing) {
    zeroOut(existing.dek);
  }
  state.dekCache.set(documentId, { dek, keyVersion });
}

// ── Utility ───────────────────────────────────────────────

function zeroOut(arr: Uint8Array | null): void {
  if (arr) {
    arr.fill(0);
  }
}
