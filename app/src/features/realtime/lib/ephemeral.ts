/**
 * E2EE Ephemeral Message Handlers
 *
 * Implements ephemeral message protocol for Yjs Awareness.
 * Uses DEK directly for encryption with 4-step session handshake.
 */

import {
  encrypt,
  decrypt,
  sign,
  verify,
  toBase64,
  fromBase64,
  fromBase64Json,
  canonicalizeAndToBase64,
  getSodium,
  SIGNATURE_DOMAINS,
  type Ed25519KeyPair,
  type SigningMessage,
} from '@/shared/lib/crypto'

// ============================================================================
// Constants
// ============================================================================

/** Session ID length in bytes */
export const SESSION_ID_LENGTH = 24

/** Counter length in bytes */
export const COUNTER_LENGTH = 4

/** Max value for initial random counter */
const MAX_INITIAL_COUNTER = 2147483647 // Math.floor(0xffffffff / 2)

// ============================================================================
// Message Types
// ============================================================================

/**
 * Ephemeral message types for session handshake.
 */
export const messageTypes = {
  /** New client announces presence */
  initialize: 1,
  /** Send proof and request proof from remote */
  proofAndRequestProof: 2,
  /** Send proof only */
  proof: 3,
  /** Actual awareness data */
  message: 4,
} as const

export type MessageType = keyof typeof messageTypes

// ============================================================================
// Types
// ============================================================================

/** Validated sessions from other clients */
export type ValidSessions = {
  [authorPublicKey: string]: {
    sessionId: string
    sessionCounter: number
  }
}

/** Ephemeral session state */
export interface EphemeralSession {
  /** Own session ID (24 bytes, Base64) */
  id: string
  /** Own counter (incremented on each send) */
  counter: number
  /** Validated sessions from other clients */
  validSessions: ValidSessions
}

/** Ephemeral message public data (not encrypted, used as AAD) */
export interface EphemeralPublicData {
  docId: string
  pubKey: string // Ed25519 signing public key (Base64)
}

/** Wire format for ephemeral messages */
export interface EphemeralMessage {
  ciphertext: string // Base64
  nonce: string // Base64
  signature: string // Base64 Ed25519
  publicData: string // Base64-encoded canonicalized JSON
}

/** Result of verifying and decrypting an ephemeral message */
export interface VerifyResult {
  /** Updated valid sessions */
  validSessions?: ValidSessions
  /** Proof to send back (if requested) */
  proof?: Uint8Array
  /** Whether to request proof from remote */
  requestProof?: boolean
  /** Decrypted content (only for message type) */
  content?: Uint8Array
  /** Error if verification failed */
  error?: Error
}

// ============================================================================
// Session Management
// ============================================================================

/**
 * Generate a random session ID.
 *
 * @returns Base64-encoded session ID (24 bytes)
 */
export async function generateSessionId(): Promise<string> {
  const bytes = new Uint8Array(SESSION_ID_LENGTH)
  crypto.getRandomValues(bytes)
  return toBase64(bytes)
}

/**
 * Generate a random initial counter.
 *
 * Using a large random initial value hides metadata about when the session started.
 *
 * @returns Random counter between 0 and MAX_INITIAL_COUNTER
 */
function generateInitialCounter(): number {
  const array = new Uint32Array(1)
  crypto.getRandomValues(array)
  return array[0] % MAX_INITIAL_COUNTER
}

/**
 * Create a new ephemeral session.
 *
 * @returns New session with random ID and counter
 */
export async function createEphemeralSession(): Promise<EphemeralSession> {
  return {
    id: await generateSessionId(),
    counter: generateInitialCounter(),
    validSessions: {},
  }
}

// ============================================================================
// Message Creation
// ============================================================================

/**
 * Create an ephemeral message.
 *
 * Message structure (before encryption):
 * [type (1 byte)] + [sessionId (24 bytes)] + [counter (4 bytes)] + [content]
 *
 * @param content - Message content (awareness update or proof)
 * @param messageType - Type of message
 * @param publicData - Public data (docId, pubKey) used as AAD
 * @param dek - Document encryption key
 * @param signatureKeyPair - Ed25519 signing key pair
 * @param session - Current session state
 * @returns Encrypted and signed ephemeral message
 */
export async function createEphemeralMessage(
  content: Uint8Array,
  messageType: MessageType,
  publicData: EphemeralPublicData,
  dek: Uint8Array,
  signatureKeyPair: Ed25519KeyPair,
  session: EphemeralSession
): Promise<{ message: EphemeralMessage; updatedSession: EphemeralSession }> {
  // Increment counter for this message
  const newCounter = session.counter + 1
  const updatedSession = { ...session, counter: newCounter }

  // Build prefixed content: [type] + [sessionId] + [counter] + [content]
  const sessionIdBytes = await fromBase64(session.id)
  const prefixedContent = prefixWithSessionInfo(
    content,
    messageTypes[messageType],
    sessionIdBytes,
    newCounter
  )

  // Encrypt with DEK
  const { ciphertext, nonce } = await encrypt(dek, prefixedContent)

  // Encode to Base64
  const ciphertextBase64 = await toBase64(ciphertext)
  const nonceBase64 = await toBase64(nonce)
  const publicDataBase64 = await canonicalizeAndToBase64(publicData)

  // Build signing message
  const signingMessage: SigningMessage = {
    ciphertext: ciphertextBase64,
    nonce: nonceBase64,
    publicData: publicDataBase64,
  }

  // Sign the message
  const signature = await sign(signatureKeyPair.privateKey, SIGNATURE_DOMAINS.EPHEMERAL, signingMessage)
  const signatureBase64 = await toBase64(signature)

  const message: EphemeralMessage = {
    ciphertext: ciphertextBase64,
    nonce: nonceBase64,
    signature: signatureBase64,
    publicData: publicDataBase64,
  }

  return { message, updatedSession }
}

/**
 * Create an initialize message to announce presence.
 */
export async function createInitializeMessage(
  publicData: EphemeralPublicData,
  dek: Uint8Array,
  signatureKeyPair: Ed25519KeyPair,
  session: EphemeralSession
): Promise<{ message: EphemeralMessage; updatedSession: EphemeralSession }> {
  // Initialize message has empty content
  return createEphemeralMessage(
    new Uint8Array(0),
    'initialize',
    publicData,
    dek,
    signatureKeyPair,
    session
  )
}

// ============================================================================
// Message Verification and Decryption
// ============================================================================

/**
 * Verify and decrypt an ephemeral message.
 *
 * @param message - Received ephemeral message
 * @param dek - Document encryption key
 * @param currentDocId - Current document ID (for validation)
 * @param session - Current session state
 * @param signatureKeyPair - Own Ed25519 key pair (for creating proofs)
 * @returns Verification result with updated sessions and/or content
 */
export async function verifyAndDecryptEphemeralMessage(
  message: EphemeralMessage,
  dek: Uint8Array,
  currentDocId: string,
  session: EphemeralSession,
  signatureKeyPair: Ed25519KeyPair
): Promise<VerifyResult> {
  try {
    // Decode publicData from Base64 string to object
    const publicData = await fromBase64Json<EphemeralPublicData>(message.publicData)

    // Validate document ID
    if (publicData.docId !== currentDocId) {
      return { validSessions: session.validSessions }
    }

    const senderPublicKey = await fromBase64(publicData.pubKey)

    // Build signing message for verification
    // Use message.publicData directly since it's already Base64-encoded
    const signingMessage: SigningMessage = {
      ciphertext: message.ciphertext,
      nonce: message.nonce,
      publicData: message.publicData,
    }

    // Verify signature
    const signature = await fromBase64(message.signature)
    const isValid = await verify(senderPublicKey, signature, SIGNATURE_DOMAINS.EPHEMERAL, signingMessage)
    if (!isValid) {
      return { error: new Error('EPHEMERAL_ERROR_308') } // Invalid signature
    }

    // Decrypt content
    const ciphertext = await fromBase64(message.ciphertext)
    const nonce = await fromBase64(message.nonce)
    let decrypted: Uint8Array
    try {
      decrypted = await decrypt(dek, ciphertext, nonce)
    } catch {
      return { error: new Error('EPHEMERAL_ERROR_301') } // Decryption failed
    }

    // Parse prefix: [type (1)] + [sessionId (24)] + [counter (4)] + [content]
    const { type, sessionId, counter, content } = await parsePrefix(decrypted)
    const senderPublicKeyBase64 = publicData.pubKey

    // Handle by message type
    switch (type) {
      case messageTypes.initialize:
        // Create proof and request proof back
        const initProof = await createEphemeralSessionProof(
          sessionId,
          session.id,
          signatureKeyPair
        )
        return {
          proof: initProof,
          requestProof: true,
          validSessions: session.validSessions,
        }

      case messageTypes.proofAndRequestProof:
      case messageTypes.proof: {
        // Verify the proof
        const isProofValid = await verifyEphemeralSessionProof(
          content,
          session.id,
          sessionId,
          senderPublicKey
        )

        if (isProofValid) {
          // Session established
          const newValidSessions: ValidSessions = {
            ...session.validSessions,
            [senderPublicKeyBase64]: {
              sessionId,
              sessionCounter: counter,
            },
          }

          // Create response proof if requested
          let responseProof: Uint8Array | undefined
          if (type === messageTypes.proofAndRequestProof) {
            responseProof = await createEphemeralSessionProof(
              sessionId,
              session.id,
              signatureKeyPair
            )
          }

          return {
            validSessions: newValidSessions,
            proof: responseProof,
            requestProof: false,
          }
        } else {
          return { validSessions: session.validSessions }
        }
      }

      case messageTypes.message: {
        const existingSession = session.validSessions[senderPublicKeyBase64]

        // Check if session is valid
        if (!existingSession || existingSession.sessionId !== sessionId) {
          // Unknown session - treat as initialize
          const msgProof = await createEphemeralSessionProof(
            sessionId,
            session.id,
            signatureKeyPair
          )
          return {
            proof: msgProof,
            requestProof: true,
            validSessions: session.validSessions,
            error: new Error('EPHEMERAL_ERROR_302'), // Session not established
          }
        }

        // Replay attack check
        if (existingSession.sessionCounter >= counter) {
          return { error: new Error('EPHEMERAL_ERROR_303') } // Replay attack
        }

        // Update counter and return content
        const newValidSessions: ValidSessions = {
          ...session.validSessions,
          [senderPublicKeyBase64]: {
            sessionId,
            sessionCounter: counter,
          },
        }

        return {
          content,
          validSessions: newValidSessions,
        }
      }

      default:
        return { error: new Error('EPHEMERAL_ERROR_305') } // Unknown message type
    }
  } catch (err) {
    console.error('[ephemeral] Error processing message:', err)
    return { error: new Error('EPHEMERAL_ERROR_307') } // General error
  }
}

// ============================================================================
// Session Proof
// ============================================================================

/**
 * Create a session proof.
 *
 * The proof is a signature over:
 * { remoteClientSessionId, currentClientSessionId }
 *
 * @param remoteSessionId - Remote client's session ID (Base64)
 * @param currentSessionId - Own session ID (Base64)
 * @param signatureKeyPair - Own Ed25519 key pair
 * @returns Proof as signature bytes
 */
export async function createEphemeralSessionProof(
  remoteSessionId: string,
  currentSessionId: string,
  signatureKeyPair: Ed25519KeyPair
): Promise<Uint8Array> {
  const sodium = await getSodium()

  // Create proof data as JSON
  const proofData = JSON.stringify({
    currentClientSessionId: currentSessionId,
    remoteClientSessionId: remoteSessionId,
  })

  // Domain + proof data
  const domain = 'refmd_ephemeral_session_proof'
  const encoder = new TextEncoder()
  const domainBytes = encoder.encode(domain)
  const dataBytes = encoder.encode(proofData)

  const messageBytes = new Uint8Array(domainBytes.length + dataBytes.length)
  messageBytes.set(domainBytes, 0)
  messageBytes.set(dataBytes, domainBytes.length)

  return sodium.crypto_sign_detached(messageBytes, signatureKeyPair.privateKey)
}

/**
 * Verify a session proof.
 *
 * @param proof - Proof bytes (signature)
 * @param expectedCurrentSessionId - Expected value of currentClientSessionId in proof
 * @param remoteSessionId - Remote client's session ID
 * @param remotePublicKey - Remote client's Ed25519 public key
 * @returns True if proof is valid
 */
export async function verifyEphemeralSessionProof(
  proof: Uint8Array,
  expectedCurrentSessionId: string,
  remoteSessionId: string,
  remotePublicKey: Uint8Array
): Promise<boolean> {
  const sodium = await getSodium()

  // Create expected proof data (note: currentClient is the remote, remoteClient is us)
  const proofData = JSON.stringify({
    currentClientSessionId: remoteSessionId,
    remoteClientSessionId: expectedCurrentSessionId,
  })

  // Domain + proof data
  const domain = 'refmd_ephemeral_session_proof'
  const encoder = new TextEncoder()
  const domainBytes = encoder.encode(domain)
  const dataBytes = encoder.encode(proofData)

  const messageBytes = new Uint8Array(domainBytes.length + dataBytes.length)
  messageBytes.set(domainBytes, 0)
  messageBytes.set(dataBytes, domainBytes.length)

  try {
    return sodium.crypto_sign_verify_detached(proof, messageBytes, remotePublicKey)
  } catch {
    return false
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Prefix content with session info.
 *
 * Format: [type (1)] + [sessionId (24)] + [counter (4)] + [content]
 */
function prefixWithSessionInfo(
  content: Uint8Array,
  type: number,
  sessionId: Uint8Array,
  counter: number
): Uint8Array {
  const counterBytes = intToUint8Array(counter)

  const result = new Uint8Array(1 + SESSION_ID_LENGTH + COUNTER_LENGTH + content.length)
  result[0] = type
  result.set(sessionId, 1)
  result.set(counterBytes, 1 + SESSION_ID_LENGTH)
  result.set(content, 1 + SESSION_ID_LENGTH + COUNTER_LENGTH)

  return result
}

/**
 * Parse prefix from decrypted content.
 */
async function parsePrefix(data: Uint8Array): Promise<{
  type: number
  sessionId: string
  counter: number
  content: Uint8Array
}> {
  const type = data[0]
  const sessionIdBytes = data.slice(1, 1 + SESSION_ID_LENGTH)
  const sessionId = await toBase64(sessionIdBytes)
  const counterBytes = data.slice(1 + SESSION_ID_LENGTH, 1 + SESSION_ID_LENGTH + COUNTER_LENGTH)
  const counter = uint8ArrayToInt(counterBytes)
  const content = data.slice(1 + SESSION_ID_LENGTH + COUNTER_LENGTH)

  return { type, sessionId, counter, content }
}

/**
 * Convert integer to 4-byte Uint8Array (big-endian).
 */
function intToUint8Array(num: number): Uint8Array {
  const arr = new Uint8Array(4)
  arr[0] = (num >> 24) & 0xff
  arr[1] = (num >> 16) & 0xff
  arr[2] = (num >> 8) & 0xff
  arr[3] = num & 0xff
  return arr
}

/**
 * Convert 4-byte Uint8Array to integer (big-endian).
 */
function uint8ArrayToInt(arr: Uint8Array): number {
  return (arr[0] << 24) | (arr[1] << 16) | (arr[2] << 8) | arr[3]
}
