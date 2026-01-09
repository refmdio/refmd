/**
 * E2EE Realtime Message Types
 *
 * Compatible with backend (api/crates/application/src/documents/ports/realtime/realtime_types.rs)
 */

/** Message types for E2EE realtime */
export type MessageType = 'update' | 'snapshot' | 'awareness'

/**
 * E2EE realtime message (JSON format over WebSocket)
 * Field names match backend (camelCase in JSON)
 */
export interface RealtimeMessage {
  /** Message type */
  type: MessageType
  /** Base64-encoded ciphertext (XChaCha20-Poly1305) */
  ciphertext: string
  /** Base64-encoded nonce (24 bytes) */
  nonce: string
  /** Base64-encoded Ed25519 signature */
  signature: string
  /** Base64-encoded canonicalized JSON publicData */
  publicData: string
}

/**
 * Update public data structure
 * Sent with each Yjs update
 */
export interface UpdatePublicData {
  /** Document ID */
  docId: string
  /** Ed25519 public key (Base64) */
  pubKey: string
  /** Reference snapshot ID */
  refSnapshotId: string
  /** Logical clock for ordering */
  clock: number
}

/**
 * Snapshot public data structure
 * Sent when creating a snapshot
 */
export interface SnapshotPublicData {
  /** Document ID */
  docId: string
  /** Ed25519 public key (Base64) */
  pubKey: string
  /** Snapshot ID */
  snapshotId: string
  /** Parent snapshot ID */
  parentSnapshotId: string
  /** Parent snapshot proof (hash chain) */
  parentSnapshotProof: string
  /** Update clocks at time of snapshot (pubKey -> clock) */
  parentSnapshotUpdateClocks: Record<string, number>
}

/**
 * Ephemeral message public data (for Awareness)
 */
export interface EphemeralPublicData {
  /** Document ID */
  docId: string
  /** Ed25519 public key (Base64) */
  pubKey: string
}

/**
 * Snapshot info with update clocks
 * Used for tracking sync state
 */
export interface SnapshotInfoWithUpdateClocks {
  /** Snapshot ID */
  snapshotId: string
  /** Hash of snapshot ciphertext */
  snapshotCiphertextHash: string
  /** Parent snapshot proof */
  parentSnapshotProof: string
  /** Update clocks at this snapshot */
  updateClocks: Record<string, number>
  /** Additional public data */
  additionalPublicData?: unknown
}

/**
 * Create a RealtimeMessage
 */
export function createRealtimeMessage(
  type: MessageType,
  ciphertext: string,
  nonce: string,
  signature: string,
  publicData: string
): RealtimeMessage {
  return {
    type,
    ciphertext,
    nonce,
    signature,
    publicData,
  }
}

/**
 * Parse public data from a realtime message
 */
export function parsePublicData<T>(publicDataBase64: string): T {
  const decoded = atob(publicDataBase64)
  return JSON.parse(decoded) as T
}

/**
 * Signature domains for E2EE messages
 */
export const SIGNATURE_DOMAINS = {
  SNAPSHOT: 'refmd_snapshot',
  UPDATE: 'refmd_update',
  EPHEMERAL: 'refmd_ephemeral',
} as const

export type SignatureDomain = typeof SIGNATURE_DOMAINS[keyof typeof SIGNATURE_DOMAINS]
