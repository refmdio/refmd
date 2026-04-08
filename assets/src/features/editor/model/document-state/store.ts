import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { documentStates, errorSignals } from "./registry";
import type { DocumentState } from "./types";

function createDocumentState(documentId: string, workspaceId: string): DocumentState {
  const existing = documentStates.get(documentId);
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
    _reauthResolvers: [],
    _rollbackResolvers: [],
    _headlessSync: false,
    readOnly: false,
    _cachedConfirmedStateVector: null,
  };
  documentStates.set(documentId, state);
  return state;
}

export async function acquireDocumentState(
  documentId: string,
  workspaceId: string,
): Promise<{
  yDoc: Y.Doc;
  awareness: Awareness;
}> {
  const existing = documentStates.get(documentId);
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
      errorSignals.get(documentId)?.[1](null);
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
    return { yDoc: existing.yDoc, awareness: existing.awareness };
  }

  const state = createDocumentState(documentId, workspaceId);
  return { yDoc: state.yDoc, awareness: state.awareness };
}

export function getDocumentState(documentId: string): DocumentState | undefined {
  return documentStates.get(documentId);
}

export function getAllActiveDocumentStates(): Map<string, DocumentState> {
  return documentStates;
}

export function getDocText(documentId: string): string | null {
  const state = documentStates.get(documentId);
  if (!state || !state.initialized) return null;
  return state.yDoc.getText("content").toString();
}
