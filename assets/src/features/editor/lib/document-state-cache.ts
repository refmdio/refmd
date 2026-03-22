import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { createSignal } from "solid-js";
import type { Channel } from "phoenix";
import { leaveDocument } from "@/shared/lib/ws/phoenix-channel";
import type { AutoSyncHandle } from "./auto-sync";

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

  // DEK (raw DEK lives in Crypto Worker only; metadata here)
  dekResolved: boolean;
  keyVersion: number;
  workspaceId: string;

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
  revokedSigningKeys: Set<string>;
  rejectedSigningKeys: Set<string>;

  // Sending lock (prevents concurrent sendPendingChanges)
  sending: boolean;

  // In-flight update state for update-saved/update-save-failed handling
  preSendLocalClock: number;
  pendingUpdateBytes: Uint8Array | null;

  // Temporary callback for initial document event (used during init)
  _onDocumentMessage: ((payload: unknown) => void) | null;
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

    dekResolved: false,
    keyVersion: 0,
    workspaceId,

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
    revokedSigningKeys: new Set(),
    rejectedSigningKeys: new Set(),
    autoSync: null,
    sending: false,
    preSendLocalClock: 0,
    pendingUpdateBytes: null,
    _onDocumentMessage: null,
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
      existing.initialized = false;
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
    setTimeout(() => {
      const current = cache.get(documentId);
      if (current && current.refCount <= 0) {
        teardownState(documentId, current);
      }
    }, EVICTION_DELAY_MS);
  }
}

function teardownState(documentId: string, state: DocumentState): void {
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  leaveDocument(documentId);
  state.channel = null;
  state.awareness.destroy();
  state.yDoc.destroy();
  cache.delete(documentId);
  errorSignals.delete(documentId);
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
