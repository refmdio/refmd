import * as Y from "yjs";
import { Awareness, removeAwarenessStates } from "y-protocols/awareness";
import { createSignal } from "solid-js";
import type { Channel } from "phoenix";
import { leaveDocument } from "@/shared/lib/ws/phoenix-channel";
import type { AutoSyncHandle } from "./auto-sync";
import type { EphemeralSession } from "./ephemeral-session";

// ── Types ────────────────────────────────────────────────────

export interface PendingSnapshot {
  snapshotId: string;
  ciphertextHash: string;
  parentSnapshotProof: string;
  snapshotYjsState: Uint8Array;
  knownClocksAtSend: Record<string, number>;
}

export interface DocumentState {
  // Y.Doc
  yDoc: Y.Doc;
  awareness: Awareness;
  refCount: number;

  // Initialization
  initialized: boolean;
  error: string | null;
  initPromise: Promise<void> | null;
  _initAbortController: AbortController | null;

  // DEK (raw DEK lives in Crypto Worker only; metadata here)
  dekResolved: boolean;
  keyVersion: number;
  pendingRotationKeyVersion: number | null;
  workspaceId: string;
  pendingRotationSnapshot: boolean;

  // Channel
  channel: Channel | null;

  // Sync state
  activeSnapshotId: string | null;
  localClock: number;
  knownClocks: Record<string, number>;
  confirmedClocks: Record<string, number>;
  lastSavedState: Uint8Array | null;
  snapshotUpdatesCount: number;

  // Snapshot proof chain
  snapshotProofHash: string;
  snapshotCiphertextHash: string;
  pendingSnapshot: PendingSnapshot | null;

  // Global version (for anti-rollback regression check)
  latestVersion: number;

  // Auto-sync
  autoSync: AutoSyncHandle | null;

  // Signing key cache for verification
  signingKeys: Map<string, Uint8Array>;
  signingKeyOwners: Map<string, string>;
  memberNames: Map<string, string>;
  revokedSigningKeys: Set<string>;
  rejectedSigningKeys: Set<string>;

  // Awareness clientID ownership: maps clientID → signingPubKey of the sender
  // who first established that clientID. Cross-owner updates are rejected.
  awarenessClientOwners: Map<number, string>;

  // Sending lock (prevents concurrent sendPendingChanges)
  sending: boolean;

  // In-flight update state for update-saved/update-save-failed handling
  preSendLocalClock: number;
  pendingUpdateBytes: Uint8Array | null;

  // In-flight envelope for reconnect replay (update_hash UNIQUE idempotency)
  pendingUpdateEnvelope: Record<string, unknown> | null;
  pendingSnapshotEnvelope: Record<string, unknown> | null;

  // Temporary callback for initial document event (used during init)
  _onDocumentMessage: ((payload: unknown) => void) | null;

  // Deferred DEK rotation retry (set by init, invoked by checkRotationSnapshot)
  _retryDekRotation: (() => Promise<void>) | null;

  // Ephemeral session for awareness relay
  ephemeralSession: EphemeralSession | null;
  awarenessRelayCleanup: (() => void) | null;

  // Reconnection guard (prevents multiple concurrent reconnect loops)
  _reconnecting: boolean;

  // Queue for events received during reconnect initialization
  _pendingRemoteEvents: Array<{ type: "update" | "snapshot"; payload: unknown }>;
  _lastJoinMode: "complete" | "delta";

  // Offline cache periodic flush cleanup
  offlineFlushCleanup: (() => void) | null;
  offlineResumeCleanup: (() => void) | null;

  // Whether this document was loaded from offline cache (not from server)
  loadedFromOfflineCache: boolean;

  // Re-authentication callback
  _reauthResolver: (() => void) | null;
  // Rollback warning approval callback
  _rollbackResolver: (() => void) | null;
  // True while the document is being synced without an attached panel/UI.
  _headlessSync: boolean;
  // Read-only mode (access revoked, document deleted, etc.)
  readOnly: boolean;

  // Cached confirmed state vector for offline pending diff computation.
  // Set from document-cache entry during offline recovery when lastSavedState is unavailable.
  _cachedConfirmedStateVector: Uint8Array | null;
}

// ── Cache ────────────────────────────────────────────────────

const cache = new Map<string, DocumentState>();

const EVICTION_DELAY_MS = 200;

export function createDocumentState(documentId: string, workspaceId: string): DocumentState {
  const existing = cache.get(documentId);
  if (existing) {
    existing.refCount++;
    return existing;
  }

  const yDoc = new Y.Doc();
  const awareness = new Awareness(yDoc);

  const state: DocumentState = {
    yDoc,
    awareness,
    refCount: 1,

    initialized: false,
    error: null,
    initPromise: null,
    _initAbortController: null,

    dekResolved: false,
    keyVersion: 0,
    workspaceId,
    pendingRotationKeyVersion: null,
    pendingRotationSnapshot: false,

    channel: null,

    activeSnapshotId: null,
    localClock: 0,
    knownClocks: {},
    confirmedClocks: {},
    lastSavedState: null,
    snapshotUpdatesCount: 0,

    snapshotProofHash: "",
    snapshotCiphertextHash: "",
    pendingSnapshot: null,
    latestVersion: 0,

    signingKeys: new Map(),
    signingKeyOwners: new Map(),
    memberNames: new Map(),
    revokedSigningKeys: new Set(),
    rejectedSigningKeys: new Set(),
    awarenessClientOwners: new Map(),
    autoSync: null,
    sending: false,
    preSendLocalClock: 0,
    pendingUpdateBytes: null,
    pendingUpdateEnvelope: null,
    pendingSnapshotEnvelope: null,
    _onDocumentMessage: null,
    _retryDekRotation: null,
    ephemeralSession: null,
    awarenessRelayCleanup: null,
    _reconnecting: false,
    _pendingRemoteEvents: [],
    _lastJoinMode: "complete",
    offlineFlushCleanup: null,
    offlineResumeCleanup: null,
    loadedFromOfflineCache: false,
    _reauthResolver: null,
    _rollbackResolver: null,
    _headlessSync: false,
    readOnly: false,
    _cachedConfirmedStateVector: null,
  };

  cache.set(documentId, state);
  return state;
}

export async function acquireDocumentState(
  documentId: string,
  workspaceId: string,
): Promise<{ yDoc: Y.Doc; awareness: Awareness }> {
  const existing = cache.get(documentId);
  if (existing) {
    existing.refCount++;
    if (existing.error) {
      existing.error = null;
      existing.initPromise = null;
      existing._initAbortController = null;
      existing.initialized = false;
      existing.offlineResumeCleanup?.();
      existing.offlineResumeCleanup = null;
      existing._headlessSync = false;
      existing.awareness.destroy();
      existing.yDoc.destroy();
      existing.yDoc = new Y.Doc();
      existing.awareness = new Awareness(existing.yDoc);
      existing.activeSnapshotId = null;
      existing.knownClocks = {};
      existing.confirmedClocks = {};
      existing.lastSavedState = null;
      existing.snapshotUpdatesCount = 0;
      existing.localClock = 0;
      existing.latestVersion = 0;
      existing.awarenessClientOwners.clear();
      existing._lastJoinMode = "complete";
      const signal = errorSignals.get(documentId);
      if (signal) signal[1](null);
    }
    if (existing.initialized) {
      return { yDoc: existing.yDoc, awareness: existing.awareness };
    }
    if (existing.initPromise) {
      try {
        await existing.initPromise;
      } catch {
        // Init failed but we keep the ref — caller is responsible for release
      }
      return { yDoc: existing.yDoc, awareness: existing.awareness };
    }
    // State exists but not initialized and no init in progress — caller will init
    return { yDoc: existing.yDoc, awareness: existing.awareness };
  }

  const state = createDocumentState(documentId, workspaceId);
  return { yDoc: state.yDoc, awareness: state.awareness };
}

export function releaseDocumentState(documentId: string): void {
  const state = cache.get(documentId);
  if (!state) return;

  state.refCount--;
  if (state.refCount <= 0) {
    if (state.initPromise && !state.initialized && !state._headlessSync) {
      void state.initPromise.catch(() => {});
      state._initAbortController?.abort();
      state._initAbortController = null;
      leaveDocument(documentId);
      state.channel = null;
    }
    setTimeout(() => {
      const current = cache.get(documentId);
      if (current && current.refCount <= 0) {
        teardownState(documentId, current);
      }
    }, EVICTION_DELAY_MS);
  }
}

function teardownState(documentId: string, state: DocumentState): void {
  state._initAbortController?.abort();
  state._initAbortController = null;
  // Final offline cache flush before teardown
  if (state.initialized && state.keyVersion > 0) {
    import("@/shared/lib/offline/cache-manager").then(
      ({ cacheDocumentState, cachePendingChanges }) => {
        cacheDocumentState(documentId, state.workspaceId, state).catch(() => {});
        cachePendingChanges(documentId, state).catch(() => {});
      },
    );
  }
  if (state.offlineFlushCleanup) {
    state.offlineFlushCleanup();
    state.offlineFlushCleanup = null;
  }
  if (state.offlineResumeCleanup) {
    state.offlineResumeCleanup();
    state.offlineResumeCleanup = null;
  }
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  cache.delete(documentId);
  errorSignals.delete(documentId);
  awarenessSignals.delete(documentId);
  removeAwarenessStates(state.awareness, [state.awareness.clientID], "local");
  state.awarenessRelayCleanup?.();
  state.awarenessRelayCleanup = null;
  state.ephemeralSession = null;
  leaveDocument(documentId);
  state.channel = null;
  state.awareness.destroy();
  state.yDoc.destroy();
}

// ── Sync acquireYDoc/releaseYDoc (backward compatibility for editors) ──

export function acquireYDoc(documentId: string): { yDoc: Y.Doc; awareness: Awareness } {
  const state = cache.get(documentId);
  if (!state) {
    throw new Error(
      `acquireYDoc: no DocumentState for ${documentId}. Call acquireDocumentState first.`,
    );
  }
  state.refCount++;
  return { yDoc: state.yDoc, awareness: state.awareness };
}

export function releaseYDoc(documentId: string): void {
  releaseDocumentState(documentId);
}

// ── Accessors ────────────────────────────────────────────────

export function getDocumentState(documentId: string): DocumentState | undefined {
  return cache.get(documentId);
}

export function getAllActiveDocumentStates(): Map<string, DocumentState> {
  return cache;
}

// ── Reactive error signals (for UI notification after init) ──

const errorSignals = new Map<string, ReturnType<typeof createSignal<string | null>>>();

function getErrorSignal(documentId: string) {
  let signal = errorSignals.get(documentId);
  if (!signal) {
    signal = createSignal<string | null>(null);
    errorSignals.set(documentId, signal);
  }
  return signal;
}

export function getDocumentError(documentId: string): string | null {
  const [getter] = getErrorSignal(documentId);
  return getter();
}

export function setDocumentError(documentId: string, error: string): void {
  const [, setError] = getErrorSignal(documentId);
  setError(error);
  const state = cache.get(documentId);
  if (state) state.error = error;
}

// ── Reactive reauth signals ──────────────────────────────────

const reauthSignals = new Map<string, ReturnType<typeof createSignal<boolean>>>();

function getReauthSignal(documentId: string) {
  let signal = reauthSignals.get(documentId);
  if (!signal) {
    signal = createSignal(false);
    reauthSignals.set(documentId, signal);
  }
  return signal;
}

export function needsReauth(documentId: string): boolean {
  const [getter] = getReauthSignal(documentId);
  return getter();
}

export function requestReauth(documentId: string): Promise<void> {
  const [, setter] = getReauthSignal(documentId);
  setter(true);
  return new Promise<void>((resolve) => {
    const state = cache.get(documentId);
    if (state) {
      state._reauthResolver = resolve;
    } else {
      resolve();
    }
  });
}

export function completeReauth(documentId: string): void {
  const [, setter] = getReauthSignal(documentId);
  setter(false);
  const state = cache.get(documentId);
  if (state?._reauthResolver) {
    state._reauthResolver();
    state._reauthResolver = null;
  }
}

// ── Reactive rollback warning signals ─────────────────────────

const rollbackSignals = new Map<string, ReturnType<typeof createSignal<string | null>>>();

function getRollbackSignal(documentId: string) {
  let signal = rollbackSignals.get(documentId);
  if (!signal) {
    signal = createSignal<string | null>(null);
    rollbackSignals.set(documentId, signal);
  }
  return signal;
}

export function getRollbackWarning(documentId: string): string | null {
  const [getter] = getRollbackSignal(documentId);
  return getter();
}

export function requestRollbackApproval(documentId: string, message: string): Promise<void> {
  const [, setter] = getRollbackSignal(documentId);
  setter(message);
  return new Promise<void>((resolve) => {
    const state = cache.get(documentId);
    if (state) {
      state._rollbackResolver = resolve;
    } else {
      resolve();
    }
  });
}

export function approveRollback(documentId: string): void {
  const [, setter] = getRollbackSignal(documentId);
  setter(null);
  const state = cache.get(documentId);
  if (state?._rollbackResolver) {
    state._rollbackResolver();
    state._rollbackResolver = null;
  }
}

// ── Reactive awareness signal (for PresenceAvatars) ──────────

const awarenessSignals = new Map<string, ReturnType<typeof createSignal<Awareness | null>>>();

function getAwarenessSignal(documentId: string) {
  let signal = awarenessSignals.get(documentId);
  if (!signal) {
    signal = createSignal<Awareness | null>(null);
    awarenessSignals.set(documentId, signal);
  }
  return signal;
}

export function getDocumentAwareness(documentId: string): Awareness | null {
  const [getter] = getAwarenessSignal(documentId);
  return getter();
}

export function notifyAwarenessReady(documentId: string): void {
  const state = cache.get(documentId);
  if (state?.awareness) {
    const [, setter] = getAwarenessSignal(documentId);
    setter(state.awareness);
  }
}

export function getDocText(documentId: string): string | null {
  const state = cache.get(documentId);
  if (!state || !state.initialized) return null;
  return state.yDoc.getText("content").toString();
}

// ── Scroll sync (carried over from ydoc-cache) ──────────────

type ScrollListener = (ratio: number, sourceId: string) => void;
const scrollListeners = new Map<string, Set<ScrollListener>>();

export function onScrollSync(scrollGroupId: string, listener: ScrollListener): () => void {
  let set = scrollListeners.get(scrollGroupId);
  if (!set) {
    set = new Set();
    scrollListeners.set(scrollGroupId, set);
  }
  set.add(listener);
  return () => {
    set!.delete(listener);
    if (set!.size === 0) scrollListeners.delete(scrollGroupId);
  };
}

export function emitScrollSync(scrollGroupId: string, ratio: number, sourceId: string): void {
  const set = scrollListeners.get(scrollGroupId);
  if (!set) return;
  for (const listener of set) {
    listener(ratio, sourceId);
  }
}
