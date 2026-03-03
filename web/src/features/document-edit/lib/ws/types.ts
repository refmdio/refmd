/**
 * WebSocket synchronization types
 */

/** Thrown when a cryptographic verification (signature, ciphertext hash, proof chain, anti-rollback) fails.
 *  The transport layer catches this to disconnect rather than proceeding with unverified state. */
export class VerificationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VerificationError'
  }
}

/** Thrown when TOFU detects an identity key change during device resolution.
 *  Callers should surface the warning to the user via the key-change dialog. */
export class TofuKeyChangeError extends Error {
  constructor(public readonly warning: import('../types').TofuKeyChangeWarning) {
    super(`TOFU key change detected for device ${warning.deviceId}`)
    this.name = 'TofuKeyChangeError'
  }
}

/** WebSocket connection states */
export type WsConnectionState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'disconnected'
  | 'failed'

/** Server → Client messages */
export type WsServerMessage =
  | WsDocumentMessage
  | WsSnapshotMessage
  | WsSnapshotSavedMessage
  | WsSnapshotSaveFailedMessage
  | WsUpdateMessage
  | WsUpdateSavedMessage
  | WsUpdateSaveFailedMessage
  | WsEphemeralMessage
  | WsDocumentNotFoundMessage
  | WsUnauthorizedMessage
  | WsDocumentErrorMessage
  | WsValidationErrorMessage

export interface WsDocumentMessage {
  type: 'document'
  snapshot: WsSnapshotData | null
  updates: WsUpdateData[]
  snapshotProofChain: WsSnapshotProofData[]
}

export interface WsSnapshotMessage {
  type: 'snapshot'
  snapshotId: string
  snapshot: WsEnvelope
}

export interface WsSnapshotSavedMessage {
  type: 'snapshot-saved'
  snapshotId: string
}

export interface WsSnapshotSaveFailedMessage {
  type: 'snapshot-save-failed'
  snapshot: WsSnapshotData | null
  updates: WsUpdateData[]
  snapshotProofChain: WsSnapshotProofData[]
}

export interface WsUpdateMessage {
  type: 'update'
  ciphertext: string
  nonce: string
  signature: string
  publicData: WsUpdatePublicData
  version: number
}

export interface WsUpdateSavedMessage {
  type: 'update-saved'
  snapshotId: string
  clock: number
  version: number
}

export interface WsUpdateSaveFailedMessage {
  type: 'update-save-failed'
  snapshotId: string
  clock: number
  requiresNewSnapshot: boolean
}

export interface WsEphemeralMessage {
  type: 'ephemeral-message'
  ciphertext: string
  nonce: string
  signature: string
  publicData: Record<string, unknown>
}

export interface WsDocumentNotFoundMessage {
  type: 'document-not-found'
}

export interface WsUnauthorizedMessage {
  type: 'unauthorized'
}

export interface WsDocumentErrorMessage {
  type: 'document-error'
}

export interface WsValidationErrorMessage {
  type: 'validation-error'
  messageType: string
  detail: string
}

/** Snapshot data from server (DB persisted) */
export interface WsSnapshotData {
  id: string
  documentId: string
  latestVersion: number
  data: string
  nonce: string
  keyVersion: number
  signature: string
  ciphertextHash: string
  clocks: Record<string, number>
  parentSnapshotUpdateClocks: Record<string, number>
  parentSnapshotProof: string
  createdByDevice: string
  publicData: Record<string, unknown>
  createdAt: string
}

/** Update data from server (DB persisted) */
export interface WsUpdateData {
  updateData: string
  nonce: string
  keyVersion: number
  updateHash: string
  signature: string
  timestamp: number
  snapshotId: string
  clock: number
  version: number
  deviceSigningPubKey: string
  publicData: Record<string, unknown>
}

/** Snapshot proof chain entry */
export interface WsSnapshotProofData {
  snapshotId: string
  ciphertextHash: string
  parentSnapshotProof: string
}

/** Client → Server envelope */
export interface WsEnvelope {
  ciphertext: string
  nonce: string
  signature: string
  publicData: Record<string, unknown>
}

/** Public data for update messages */
export interface WsUpdatePublicData {
  docId: string
  deviceId: string
  signingPubKey: string
  keyVersion: number
  refSnapshotId: string
  clock: number
  timestamp: number
  updateHash: string
}

/** Queued message waiting to be sent or confirmed */
export interface QueuedMessage {
  envelope: WsEnvelope
  type: 'update' | 'snapshot' | 'ephemeral'
  clock?: number
  refSnapshotId?: string
  /** Y.Doc state before this update was sent (for rollback on failure) */
  preSendState?: Uint8Array
  /** Local clock value before this send (for rollback on failure) */
  preSendLocalClock?: number
  /** Device signing pub key for this update (for clock rollback) */
  deviceSigningPubKey?: string
}

/** Connection mode used for the current WebSocket session */
export type WsConnectionMode = 'complete' | 'delta'

/** WebSocket sync message callbacks (data handling only, no UI state) */
export interface WsSyncCallbacks {
  /** Handle initial document message. Throw VerificationError on verification failure to trigger disconnect. */
  onDocument: (msg: WsDocumentMessage, mode: WsConnectionMode) => Promise<void> | void
  onUpdate: (msg: WsUpdateMessage) => Promise<void> | void
  /** Handle remote snapshot broadcast. Throw VerificationError on verification failure to trigger disconnect. */
  onSnapshot: (msg: WsSnapshotMessage) => Promise<void> | void
  onSnapshotSaved: (msg: WsSnapshotSavedMessage) => void
  /** Handle snapshot save rejection. Throw VerificationError on verification failure to trigger disconnect. */
  onSnapshotSaveFailed: (msg: WsSnapshotSaveFailedMessage) => Promise<void> | void
  onUpdateSaved: (msg: WsUpdateSavedMessage) => void
  onUpdateSaveFailed: (msg: WsUpdateSaveFailedMessage) => void
  onEphemeral: (msg: WsEphemeralMessage) => Promise<void> | void
}
