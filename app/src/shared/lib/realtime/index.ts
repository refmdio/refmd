/**
 * Realtime Sync Module
 *
 * Provides encrypted Yjs synchronization over WebSocket.
 * Replaces y-websocket with encrypted communication.
 */

// Main sync functionality
export {
  createConnection,
  Sync,
  type Connection,
  type ConnectionOptions,
  type SyncState,
  type SyncStatus,
  type StatusEvent,
  type StatusEventHandler,
} from './sync'

// Message creation and verification
export {
  createUpdate,
  createSnapshot,
  verifyAndDecryptUpdate,
  verifyAndDecryptSnapshot,
  decryptInitSnapshot,
  decryptSyncUpdate,
  isServerInitMessage,
  isServerSyncUpdate,
  isRealtimeMessage,
  type ServerInitMessage,
  type ServerSyncUpdate,
  type ServerMessage,
  type DecryptedUpdate,
  type DecryptedSnapshot,
  type DecryptedInit,
  type DecryptedSyncUpdate,
  type RealtimeMessage,
  type UpdatePublicData,
  type SnapshotPublicData,
  type EphemeralPublicData,
} from './messages'

// Ephemeral (awareness) - session management with 4-step handshake
export {
  // Session management
  createEphemeralSession,
  generateSessionId,
  // Message creation
  createEphemeralMessage,
  createInitializeMessage,
  // Message verification
  verifyAndDecryptEphemeralMessage,
  // Session proof
  createEphemeralSessionProof,
  verifyEphemeralSessionProof,
  // Message types
  messageTypes,
  // Constants
  SESSION_ID_LENGTH,
  COUNTER_LENGTH,
  // Types
  type MessageType,
  type ValidSessions,
  type EphemeralSession,
  type EphemeralPublicData as EphemeralPublicDataType,
  type EphemeralMessage,
  type VerifyResult,
} from './ephemeral'
