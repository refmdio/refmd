import type * as Y from "yjs";
import type { Awareness } from "y-protocols/awareness";
import type { Channel } from "phoenix";
import type { RemoteSnapshotPayload, UpdatePayload } from "@/shared/lib/ws/document-payloads";
import type { EphemeralSession } from "../../lib/sync/ephemeral/session";

interface PendingSnapshot {
  snapshotId: string;
  ciphertextHash: string;
  parentSnapshotProof: string;
  snapshotYjsState: Uint8Array;
  knownClocksAtSend: Record<string, number>;
}

export interface AutoSyncHandle {
  dispose: () => void;
  notifyLocalEdit: () => void;
  flush: () => void;
}

export interface DocumentState {
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
  lastSavedState: Uint8Array | null;
  snapshotUpdatesCount: number;
  snapshotProofHash: string;
  snapshotCiphertextHash: string;
  pendingSnapshot: PendingSnapshot | null;
  latestVersion: number;
  autoSync: AutoSyncHandle | null;
  signingKeys: Map<string, Uint8Array>;
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
  _lastJoinMode: "complete" | "delta";
  offlineFlushCleanup: (() => void) | null;
  offlineResumeCleanup: (() => void) | null;
  loadedFromOfflineCache: boolean;
  _reauthResolvers: Array<() => void>;
  _rollbackResolvers: Array<() => void>;
  _headlessSync: boolean;
  readOnly: boolean;
  _cachedConfirmedStateVector: Uint8Array | null;
}

export interface TeardownOptions {
  flushCache?: boolean;
}
