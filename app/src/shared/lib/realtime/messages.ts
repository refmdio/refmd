/**
 * E2EE Realtime Message Handlers
 *
 * Functions for creating and processing encrypted Yjs updates and snapshots.
 * Compatible with backend (api/crates/infrastructure/src/documents/realtime/hub.rs)
 */

import {
  encrypt,
  decrypt,
  sign,
  verify,
  SIGNATURE_DOMAINS,
  type SigningMessage,
  canonicalizeAndToBase64,
  toBase64,
  fromBase64,
  fromBase64Json,
  type RealtimeMessage,
  type UpdatePublicData,
  type SnapshotPublicData,
  type EphemeralPublicData,
  createRealtimeMessage,
} from '@/features/e2ee'

// Ephemeral messages are now handled by ephemeral.ts
// See: createEphemeralMessage, verifyAndDecryptEphemeralMessage

// Re-export types for consumers
export type { RealtimeMessage, UpdatePublicData, SnapshotPublicData, EphemeralPublicData }

// ============================================
// Types for server messages
// ============================================

/** Server init message (snapshot + seq) */
export interface ServerInitMessage {
  type: 'init'
  snapshot: {
    data: string // Base64 encrypted Yjs state
    nonce: string // Base64 nonce
    signature: string // Base64 Ed25519 signature
    seq_at_snapshot: number // Sequence number at snapshot
  }
}

/** Server sync_update message */
export interface ServerSyncUpdate {
  type: 'sync_update'
  update: {
    data: string // Base64 encrypted Yjs update
    nonce: string // Base64 nonce
    signature: string // Base64 Ed25519 signature
    public_key: string // Base64 Ed25519 public key
    seq: number // Sequence number
  }
}

/** Union type for all server messages */
export type ServerMessage = ServerInitMessage | ServerSyncUpdate | RealtimeMessage

// ============================================
// Create functions (client -> server)
// ============================================

/**
 * Create an encrypted and signed update message.
 *
 * @param update - Raw Yjs update bytes
 * @param dek - Document encryption key (32 bytes)
 * @param signingKeyPair - Ed25519 key pair for signing
 * @param publicData - Update metadata
 * @returns RealtimeMessage ready to send
 */
export async function createUpdate(
  update: Uint8Array,
  dek: Uint8Array,
  signingKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
  publicData: UpdatePublicData
): Promise<RealtimeMessage> {
  // 1. Encrypt the update
  const { ciphertext, nonce } = await encrypt(dek, update)

  // 2. Encode to Base64
  const ciphertextBase64 = await toBase64(ciphertext)
  const nonceBase64 = await toBase64(nonce)
  const publicDataBase64 = await canonicalizeAndToBase64(publicData)

  // 3. Build signing message
  const signingMessage: SigningMessage = {
    ciphertext: ciphertextBase64,
    nonce: nonceBase64,
    publicData: publicDataBase64,
  }

  // 4. Sign the message
  const signature = await sign(signingKeyPair.privateKey, SIGNATURE_DOMAINS.UPDATE, signingMessage)
  const signatureBase64 = await toBase64(signature)

  // 5. Create RealtimeMessage
  return createRealtimeMessage('update', ciphertextBase64, nonceBase64, signatureBase64, publicDataBase64)
}

/**
 * Create an encrypted and signed snapshot message.
 *
 * @param snapshot - Raw Yjs snapshot bytes (from Y.encodeStateAsUpdateV2)
 * @param dek - Document encryption key (32 bytes)
 * @param signingKeyPair - Ed25519 key pair for signing
 * @param publicData - Snapshot metadata
 * @returns RealtimeMessage ready to send
 */
export async function createSnapshot(
  snapshot: Uint8Array,
  dek: Uint8Array,
  signingKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
  publicData: SnapshotPublicData
): Promise<RealtimeMessage> {
  // 1. Encrypt the snapshot
  const { ciphertext, nonce } = await encrypt(dek, snapshot)

  // 2. Encode to Base64
  const ciphertextBase64 = await toBase64(ciphertext)
  const nonceBase64 = await toBase64(nonce)
  const publicDataBase64 = await canonicalizeAndToBase64(publicData)

  // 3. Build signing message
  const signingMessage: SigningMessage = {
    ciphertext: ciphertextBase64,
    nonce: nonceBase64,
    publicData: publicDataBase64,
  }

  // 4. Sign the message
  const signature = await sign(signingKeyPair.privateKey, SIGNATURE_DOMAINS.SNAPSHOT, signingMessage)
  const signatureBase64 = await toBase64(signature)

  // 5. Create RealtimeMessage
  return createRealtimeMessage('snapshot', ciphertextBase64, nonceBase64, signatureBase64, publicDataBase64)
}

// NOTE: createAwareness has been removed.
// Use createEphemeralMessage from ephemeral.ts for awareness messages.

// ============================================
// Verify and Decrypt functions (for relayed messages)
// ============================================

/** Result of verifying and decrypting an update */
export interface DecryptedUpdate {
  /** Decrypted Yjs update bytes */
  update: Uint8Array
  /** Parsed public data */
  publicData: UpdatePublicData
}

/** Result of verifying and decrypting a snapshot */
export interface DecryptedSnapshot {
  /** Decrypted Yjs snapshot bytes */
  snapshot: Uint8Array
  /** Parsed public data */
  publicData: SnapshotPublicData
}

/**
 * Verify and decrypt an update message from another client.
 *
 * @param message - Received RealtimeMessage
 * @param dek - Document encryption key (32 bytes)
 * @returns Decrypted update with public data
 * @throws Error if signature verification fails or decryption fails
 */
export async function verifyAndDecryptUpdate(
  message: RealtimeMessage,
  dek: Uint8Array
): Promise<DecryptedUpdate> {
  if (message.type !== 'update') {
    throw new Error(`Expected update message, got ${message.type}`)
  }

  // 1. Parse public data to get sender's public key
  const publicData = await fromBase64Json<UpdatePublicData>(message.publicData)
  const senderPublicKey = await fromBase64(publicData.pubKey)

  // 2. Build signing message for verification
  const signingMessage: SigningMessage = {
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    publicData: message.publicData,
  }

  // 3. Verify signature
  const signature = await fromBase64(message.signature)
  const isValid = await verify(senderPublicKey, signature, SIGNATURE_DOMAINS.UPDATE, signingMessage)

  if (!isValid) {
    throw new Error('Update signature verification failed')
  }

  // 4. Decrypt the update
  const ciphertext = await fromBase64(message.ciphertext)
  const nonce = await fromBase64(message.nonce)
  const update = await decrypt(dek, ciphertext, nonce)

  return { update, publicData }
}

/**
 * Verify and decrypt a snapshot message from another client.
 *
 * @param message - Received RealtimeMessage
 * @param dek - Document encryption key (32 bytes)
 * @returns Decrypted snapshot with public data
 * @throws Error if signature verification fails or decryption fails
 */
export async function verifyAndDecryptSnapshot(
  message: RealtimeMessage,
  dek: Uint8Array
): Promise<DecryptedSnapshot> {
  if (message.type !== 'snapshot') {
    throw new Error(`Expected snapshot message, got ${message.type}`)
  }

  // 1. Parse public data to get sender's public key
  const publicData = await fromBase64Json<SnapshotPublicData>(message.publicData)
  const senderPublicKey = await fromBase64(publicData.pubKey)

  // 2. Build signing message for verification
  const signingMessage: SigningMessage = {
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    publicData: message.publicData,
  }

  // 3. Verify signature
  const signature = await fromBase64(message.signature)
  const isValid = await verify(senderPublicKey, signature, SIGNATURE_DOMAINS.SNAPSHOT, signingMessage)

  if (!isValid) {
    throw new Error('Snapshot signature verification failed')
  }

  // 4. Decrypt the snapshot
  const ciphertext = await fromBase64(message.ciphertext)
  const nonce = await fromBase64(message.nonce)
  const snapshot = await decrypt(dek, ciphertext, nonce)

  return { snapshot, publicData }
}

// NOTE: verifyAndDecryptAwareness has been removed.
// Use verifyAndDecryptEphemeralMessage from ephemeral.ts for awareness messages.

// ============================================
// Server message decryption (init, sync_update)
// ============================================

/** Result of decrypting an init message */
export interface DecryptedInit {
  /** Decrypted Yjs snapshot bytes */
  snapshot: Uint8Array
  /** Sequence number at snapshot */
  seqAtSnapshot: number
}

/** Result of decrypting a sync_update message */
export interface DecryptedSyncUpdate {
  /** Decrypted Yjs update bytes */
  update: Uint8Array
  /** Sequence number */
  seq: number
  /** Sender's public key */
  publicKey: Uint8Array
}

/**
 * Decrypt an init message from the server.
 * Server has already verified the signature.
 *
 * @param message - Server init message
 * @param dek - Document encryption key (32 bytes)
 * @returns Decrypted snapshot
 */
export async function decryptInitSnapshot(
  message: ServerInitMessage,
  dek: Uint8Array
): Promise<DecryptedInit> {
  const ciphertext = await fromBase64(message.snapshot.data)
  const nonce = await fromBase64(message.snapshot.nonce)
  const snapshot = await decrypt(dek, ciphertext, nonce)

  return {
    snapshot,
    seqAtSnapshot: message.snapshot.seq_at_snapshot,
  }
}

/**
 * Decrypt a sync_update message from the server.
 * Server has already verified the signature.
 *
 * @param message - Server sync_update message
 * @param dek - Document encryption key (32 bytes)
 * @returns Decrypted update
 */
export async function decryptSyncUpdate(
  message: ServerSyncUpdate,
  dek: Uint8Array
): Promise<DecryptedSyncUpdate> {
  const ciphertext = await fromBase64(message.update.data)
  const nonce = await fromBase64(message.update.nonce)
  const update = await decrypt(dek, ciphertext, nonce)
  const publicKey = await fromBase64(message.update.public_key)

  return {
    update,
    seq: message.update.seq,
    publicKey,
  }
}

// ============================================
// Message type detection
// ============================================

/**
 * Check if a message is a server init message.
 */
export function isServerInitMessage(msg: unknown): msg is ServerInitMessage {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as ServerInitMessage).type === 'init' &&
    'snapshot' in msg
  )
}

/**
 * Check if a message is a server sync_update message.
 */
export function isServerSyncUpdate(msg: unknown): msg is ServerSyncUpdate {
  return (
    typeof msg === 'object' &&
    msg !== null &&
    (msg as ServerSyncUpdate).type === 'sync_update' &&
    'update' in msg
  )
}

/**
 * Check if a message is a relayed RealtimeMessage.
 */
export function isRealtimeMessage(msg: unknown): msg is RealtimeMessage {
  if (typeof msg !== 'object' || msg === null) return false
  const m = msg as RealtimeMessage
  return (
    (m.type === 'update' || m.type === 'snapshot' || m.type === 'awareness') &&
    typeof m.ciphertext === 'string' &&
    typeof m.nonce === 'string' &&
    typeof m.signature === 'string' &&
    typeof m.publicData === 'string'
  )
}
