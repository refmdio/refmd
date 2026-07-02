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
    writeSessionPromise: null,
    writeSessionReadyAt: null,
    writeSessionError: null,
    verifiedWriteSessions: new Map(),
    pendingVerifiedWriteSessions: new Map(),
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
    _lastCacheRestore: null,
    _lastJoinDecision: null,
    offlineFlushCleanup: null,
    offlineResumeCleanup: null,
    loadedFromOfflineCache: false,
    _verifiedContentPreviewReady: false,
    _verifiedContentPreviewResolvers: [],
    _reauthResolvers: [],
    _headlessSync: false,
    _preAutoSyncUserEdit: false,
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
      existing._verifiedContentPreviewReady = false;
      existing._verifiedContentPreviewResolvers.splice(0).forEach((resolve) => resolve());
      existing._preAutoSyncUserEdit = false;
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
      existing.writeSessionPromise = null;
      existing.writeSessionReadyAt = null;
      existing.writeSessionError = null;
      existing.verifiedWriteSessions.clear();
      existing.awarenessClientOwners.clear();
      existing._pendingOutOfOrderUpdates = [];
      existing._drainingOutOfOrderUpdates = false;
      if (existing._syncGapTimer) {
        clearTimeout(existing._syncGapTimer);
        existing._syncGapTimer = null;
      }
      existing._onRecoverableSyncGap = null;
      existing._lastJoinMode = "complete";
      existing._lastCacheRestore = null;
      existing._lastJoinDecision = null;
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

export function notifyDocumentVerifiedContentPreviewReady(state: DocumentState): void {
  state._verifiedContentPreviewReady = true;
  const resolvers = state._verifiedContentPreviewResolvers.splice(0);
  for (const resolve of resolvers) resolve();
}

export function waitForDocumentVerifiedContentPreview(
  stateKey: string,
  initPromise?: Promise<unknown> | null,
): Promise<void> {
  const state = documentStates.get(stateKey);
  if (!state) return Promise.reject(new Error("document_state_missing"));
  if (state._verifiedContentPreviewReady || state.initialized) return Promise.resolve();

  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      const index = state._verifiedContentPreviewResolvers.indexOf(onReady);
      if (index >= 0) state._verifiedContentPreviewResolvers.splice(index, 1);
    };
    const onReady = () => {
      if (settled) return;
      settled = true;
      cleanup();
      const current = documentStates.get(stateKey);
      if (!current || (!current._verifiedContentPreviewReady && !current.initialized)) {
        reject(new Error("document_content_preview_unavailable"));
        return;
      }
      resolve();
    };
    state._verifiedContentPreviewResolvers.push(onReady);
    void initPromise?.catch((error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    });
  });
}

export function getAllActiveDocumentStates(): Map<string, DocumentState> {
  return documentStates;
}

export function getDocText(documentId: string): string | null {
  const state = documentStates.get(documentId);
  if (!state || !state.initialized) return null;
  return state.yDoc.getText("content").toString();
}
