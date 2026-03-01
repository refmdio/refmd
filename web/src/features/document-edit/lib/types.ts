import type * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import type { TofuVerifyResult } from '@/shared/lib/crypto'
import type { DocumentWebSocket } from './ws'
import type { AutoSyncHandle } from './auto-sync'

export interface TofuKeyChangeWarning {
  deviceId: string
  oldFingerprint: string
  newFingerprint: string
  tofuResult: TofuVerifyResult
}

export interface DocumentState {
  yDoc: Y.Doc
  awareness: Awareness
  dek: Uint8Array
  keyVersion: number
  lastSavedState: Uint8Array | null
  refCount: number
  /** Current active collab snapshot ID (null = no snapshot yet, new document) */
  activeSnapshotId: string | null
  /** BLAKE3 proof hash of the snapshot chain head (for anti-rollback) */
  snapshotProofHash: string
  /** BLAKE3 ciphertext hash of the active snapshot (for proof chain computation) */
  snapshotCiphertextHash: string
  /** Per-device monotonic clock (next value to use for this device) */
  localClock: number
  /**
   * Known clocks for all devices { deviceSigningPubKey: latestClock }.
   *
   * Includes optimistic (pre-confirmation) values for the local device.
   * This is correct because TCP ordering guarantees the server processes
   * updates in send order — so if we sent clock N, all clocks < N have
   * already been processed. Used for snapshot creation (parentSnapshotUpdateClocks)
   * where we need the full picture including in-flight updates.
   *
   * Reset from confirmedClocks on reconnect (optimistic values become stale
   * when the connection drops).
   */
  knownClocks: Record<string, number>
  /**
   * Server-confirmed clocks only { deviceSigningPubKey: latestConfirmedClock }.
   *
   * Updated only when the server sends update-saved or returns updates in
   * document/snapshot-save-failed messages. Used for delta reconnect
   * (knownSnapshotUpdateClocks query param) to avoid skipping unconfirmed
   * updates that the server may not have persisted yet.
   */
  confirmedClocks: Record<string, number>
  /** Number of updates in the current snapshot (for snapshot creation threshold) */
  snapshotUpdatesCount: number
  /** WebSocket connection for real-time sync (null = not yet connected) */
  ws: DocumentWebSocket | null
  /** Number of active panels sharing this WS connection */
  wsRefCount: number
  /** Auto-sync handle (null = not started) */
  autoSync: AutoSyncHandle | null
  /** Device signing key cache for verifying remote updates */
  signingKeys: Map<string, Uint8Array>
  /** Pending snapshot metadata (set before send, consumed on snapshot-saved) */
  pendingSnapshot: {
    /** Client-generated snapshot ID (included in signed publicData) */
    snapshotId: string
    ciphertextHash: string
    parentSnapshotProof: string
    /** Y.Doc state at snapshot creation time — used to reset lastSavedState on snapshot-saved */
    snapshotYjsState: Uint8Array
  } | null
  /** True after the first WS `document` message has been processed */
  initialized: boolean
}
