import type * as Y from "yjs";
import type { Awareness } from "y-protocols/awareness";
import type { Channel } from "phoenix";
import type { RemoteSnapshotPayload, UpdatePayload } from "@/shared/lib/ws/document-payloads";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import type { EphemeralSession } from "../../lib/sync/ephemeral-session";
import type { DocumentAccess } from "./access";

interface PendingSnapshot {
  snapshotId: string;
  parentSnapshotId: string;
  ciphertextHash: string;
  parentProofHash: string;
  snapshotYjsState: Uint8Array;
  knownClocksAtSend: Record<string, number>;
}

export interface AutoSyncHandle {
  dispose: () => void;
  notifyLocalEdit: () => void;
  flush: () => void;
  flushNow: () => Promise<void>;
}

export interface PublicationState {
  isPublished: boolean;
  updatedAt: string | null;
}

export interface DocumentState {
  stateKey: string;
  documentId: string;
  access: DocumentAccess;
  yDoc: Y.Doc;
  awareness: Awareness;
  refCount: number;
  initialized: boolean;
  error: string | null;
  initPromise: Promise<void> | null;
  _initAbortController: AbortController | null;
  dekResolved: boolean;
  keyVersion: number;
  pendingRotationKeyVersion: number | null;
  workspaceId: string;
  pendingRotationSnapshot: boolean;
  channel: Channel | null;
  activeSnapshotId: string | null;
  localClock: number;
  knownClocks: Record<string, number>;
  confirmedClocks: Record<string, number>;
  snapshotBaseClocks: Record<string, number>;
  lastSavedState: Uint8Array | null;
  snapshotUpdatesCount: number;
  snapshotProofHash: string;
  snapshotCiphertextHash: string;
  pendingSnapshot: PendingSnapshot | null;
  latestVersion: number;
  authorityPermissionVersion: number;
  autoSync: AutoSyncHandle | null;
  signingKeys: Map<string, HybridSigningPublicKeyMaterial>;
  historicalSigningKeys: Map<string, HybridSigningPublicKeyMaterial>;
  signingKeyOwners: Map<string, string>;
  memberNames: Map<string, string>;
  revokedSigningKeys: Set<string>;
  rejectedSigningKeys: Set<string>;
  awarenessClientOwners: Map<number, string>;
  sending: boolean;
  preSendLocalClock: number;
  pendingUpdateBytes: Uint8Array | null;
  pendingUpdateEnvelope: Record<string, unknown> | null;
  pendingSnapshotEnvelope: Record<string, unknown> | null;
  _onDocumentMessage: ((payload: unknown) => void) | null;
  _retryDekRotation: (() => Promise<void>) | null;
  ephemeralSession: EphemeralSession | null;
  awarenessRelayCleanup: (() => void) | null;
  _reconnecting: boolean;
  _reconnectTimer: ReturnType<typeof setTimeout> | null;
  _syncPaused: boolean;
  _pendingRemoteEvents: Array<
    | {
        type: "update";
        payload: UpdatePayload;
      }
    | {
        type: "snapshot";
        payload: RemoteSnapshotPayload;
      }
  >;
  _pendingOutOfOrderUpdates: UpdatePayload[];
  _drainingOutOfOrderUpdates: boolean;
  _syncGapTimer: ReturnType<typeof setTimeout> | null;
  _onRecoverableSyncGap: ((err: unknown) => void) | null;
  _lastJoinMode: "complete" | "delta";
  _forceCompleteReconnect: boolean;
  offlineFlushCleanup: (() => void) | null;
  offlineResumeCleanup: (() => void) | null;
  loadedFromOfflineCache: boolean;
  _reauthResolvers: Array<() => void>;
  _headlessSync: boolean;
  readOnly: boolean;
  writerLockCleanup: (() => void) | null;
  pendingSaveTimeout: ReturnType<typeof setTimeout> | null;
  publicationState: PublicationState;
  canSyncPublication: boolean;
  lastPublicationContentHash: string | null;
  _cachedConfirmedStateVector: Uint8Array | null;
  _applyingRemote: boolean;
}

export interface TeardownOptions {
  flushCache?: boolean;
}
