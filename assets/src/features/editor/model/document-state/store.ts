import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { leaveDocument } from "@/shared/lib/ws/phoenix-channel";
import { documentStates, errorSignals, syncPausedSignals } from "./registry";
import { canSharedAccessWriteDurably, getRegisteredDocumentAccess } from "./access";
import type { DocumentState } from "./types";

function createDocumentState(
  documentId: string,
  workspaceId: string,
  stateKey: string,
): DocumentState {
  const existing = documentStates.get(stateKey);
  if (existing) {
    existing.refCount++;
    return existing;
  }

  const yDoc = new Y.Doc();
  const awareness = new Awareness(yDoc);
  const access = getRegisteredDocumentAccess(stateKey) ?? { kind: "workspace" as const };
  const state: DocumentState = {
    stateKey,
    documentId,
    access,
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
    writeSessionCounters: {},
    snapshotBaseClocks: {},
    lastSavedState: null,
    snapshotUpdatesCount: 0,
    snapshotProofHash: "",
    snapshotCiphertextHash: "",
    pendingSnapshot: null,
    latestVersion: 0,
    authorityPermissionVersion: 1,
    signingKeys: new Map(),
    historicalSigningKeys: new Map(),
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
    _admissionDirectoryRefreshRequired: false,
    writeSession: null,
    _onDocumentMessage: null,
    _retryDekRotation: null,
    ephemeralSession: null,
    awarenessRelayCleanup: null,
    _reconnecting: false,
    _reconnectTimer: null,
    _syncPaused: false,
    _pendingRemoteEvents: [],
    _pendingOutOfOrderUpdates: [],
    _drainingOutOfOrderUpdates: false,
    _syncGapTimer: null,
    _onRecoverableSyncGap: null,
    _lastJoinMode: "complete",
    _forceCompleteReconnect: false,
    offlineFlushCleanup: null,
    offlineResumeCleanup: null,
    loadedFromOfflineCache: false,
    _reauthResolvers: [],
    _headlessSync: false,
    readOnly: access.kind === "share" ? !canSharedAccessWriteDurably(access) : false,
    writerLockCleanup: null,
    pendingSaveTimeout: null,
    _pendingSaveWatchdogKind: null,
    _pendingSaveWatchdogStartedAt: null,
    _recentSaveEvents: [],
    publicationState: { isPublished: false, updatedAt: null },
    canSyncPublication: false,
    lastPublicationContentHash: null,
    _cachedConfirmedStateVector: null,
    _applyingRemote: false,
  };
  documentStates.set(stateKey, state);
  return state;
}

export async function acquireDocumentState(
  documentId: string,
  workspaceId: string,
  stateKey = documentId,
): Promise<{
  yDoc: Y.Doc;
  awareness: Awareness;
}> {
  const existing = documentStates.get(stateKey);
  if (existing) {
    existing.refCount++;
    if (existing.error) {
      leaveDocument(existing.documentId, existing.stateKey);
      existing.error = null;
      existing.initPromise = null;
      existing._initAbortController = null;
      existing.initialized = false;
      existing.channel = null;
      existing._onDocumentMessage = null;
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
      existing.writeSessionCounters = {};
      existing.snapshotBaseClocks = {};
      existing.lastSavedState = null;
      existing.snapshotUpdatesCount = 0;
      existing.localClock = 0;
      existing.latestVersion = 0;
      existing._admissionDirectoryRefreshRequired = false;
      existing.writeSession = null;
      existing.awarenessClientOwners.clear();
      existing._pendingOutOfOrderUpdates = [];
      existing._drainingOutOfOrderUpdates = false;
      if (existing._syncGapTimer) {
        clearTimeout(existing._syncGapTimer);
        existing._syncGapTimer = null;
      }
      existing._onRecoverableSyncGap = null;
      existing._lastJoinMode = "complete";
      if (existing._reconnectTimer) {
        clearTimeout(existing._reconnectTimer);
        existing._reconnectTimer = null;
      }
      existing._syncPaused = false;
      syncPausedSignals.get(stateKey)?.[1](false);
      errorSignals.get(stateKey)?.[1](null);
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

  const state = createDocumentState(documentId, workspaceId, stateKey);
  return { yDoc: state.yDoc, awareness: state.awareness };
}

export function getDocumentState(stateKey: string): DocumentState | undefined {
  return documentStates.get(stateKey);
}

export function getAllActiveDocumentStates(): Map<string, DocumentState> {
  return documentStates;
}

export function getDocText(documentId: string): string | null {
  const state = documentStates.get(documentId);
  if (!state || !state.initialized) return null;
  return state.yDoc.getText("content").toString();
}
