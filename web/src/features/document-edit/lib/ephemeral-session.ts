/**
 * Ephemeral Session Proof Exchange
 *
 * Implements a 3-message handshake for anti-impersonation:
 *   1. initialize:           A → B  (sessionIdA, no proof)
 *   2. proofAndRequestProof: B → A  (sessionIdB, proofB→A)
 *   3. proof:                A → B  (sessionIdA, proofA→B)
 *
 * After the handshake, both peers are mutually trusted and can exchange
 * `message` type payloads (e.g. Awareness updates) with replay prevention
 * via a per-session monotonic counter.
 *
 * Binary format of decrypted ephemeral content:
 *   [1B type][24B sessionId][4B counter LE][payload]
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import {
  base64UrlEncode,
  WS_SIGNATURE_PREFIX,
  canonicalizeBytes,
} from '@/shared/lib/crypto'

// =============================================================================
// Constants
// =============================================================================

export const MSG_INITIALIZE = 1
export const MSG_PROOF_AND_REQUEST = 2
export const MSG_PROOF = 3
export const MSG_MESSAGE = 4

const SESSION_ID_LEN = 24
const COUNTER_LEN = 4
const HEADER_LEN = 1 + SESSION_ID_LEN + COUNTER_LEN // 29

/**
 * Maximum number of entries in trustedPeers / pendingInitializes.
 * When the cap is reached, the oldest entry (lowest lastCounter) is
 * evicted to make room. This prevents both unbounded memory growth
 * and permanent saturation from session ID churn.
 */
const MAX_PEERS = 256
const MAX_PENDING = 256

// =============================================================================
// Types
// =============================================================================

export interface TrustedPeer {
  lastCounter: number
  signingPubKey: string // base64url
}

export interface PendingPeer {
  signingPubKey: string // base64url — expected key for the proof response
  lastCounter: number   // replay prevention during handshake
}

export interface EphemeralSession {
  sessionId: Uint8Array // 24 bytes random
  sessionCounter: number // monotonic outbound counter
  trustedPeers: Map<string, TrustedPeer> // b64url(remoteSessionId) → peer
  pendingInitializes: Map<string, PendingPeer> // b64url(remoteSessionId) → pending peer state
  /** True after we've broadcast an initialize. proofAndRequestProof is only
   *  accepted when this flag is set (enforces 3-step handshake order). */
  initializeSent: boolean
}

export interface DecodedEphemeral {
  messageType: number
  sessionId: Uint8Array
  counter: number
  payload: Uint8Array
}

export type EphemeralAction =
  | { action: 'respond'; responsePayload: Uint8Array }
  | { action: 'trusted'; awarenessData?: undefined }
  | { action: 'awareness'; awarenessData: Uint8Array }
  | { action: 'reject'; reason: string }

// =============================================================================
// Session lifecycle
// =============================================================================

export function createEphemeralSession(): EphemeralSession {
  return {
    sessionId: randomBytes(SESSION_ID_LEN),
    sessionCounter: 0,
    trustedPeers: new Map(),
    pendingInitializes: new Map(),
    initializeSent: false,
  }
}

/** Evict the oldest entry (lowest lastCounter) from a map to make room. */
function evictOldestTrusted(map: Map<string, TrustedPeer>): void {
  let oldestKey: string | undefined
  let oldestCounter = Infinity
  for (const [key, peer] of map) {
    if (peer.lastCounter < oldestCounter) {
      oldestCounter = peer.lastCounter
      oldestKey = key
    }
  }
  if (oldestKey) map.delete(oldestKey)
}

function evictOldestPending(map: Map<string, PendingPeer>): void {
  let oldestKey: string | undefined
  let oldestCounter = Infinity
  for (const [key, peer] of map) {
    if (peer.lastCounter < oldestCounter) {
      oldestCounter = peer.lastCounter
      oldestKey = key
    }
  }
  if (oldestKey) map.delete(oldestKey)
}

// =============================================================================
// Encode / Decode
// =============================================================================

/**
 * Encode an ephemeral payload with header.
 * Increments the session counter after encoding.
 */
export function encodeEphemeralPayload(
  session: EphemeralSession,
  messageType: number,
  payload: Uint8Array,
): Uint8Array {
  const result = new Uint8Array(HEADER_LEN + payload.length)
  result[0] = messageType
  result.set(session.sessionId, 1)
  const counter = session.sessionCounter++
  new DataView(result.buffer, result.byteOffset).setUint32(1 + SESSION_ID_LEN, counter, true)
  result.set(payload, HEADER_LEN)
  return result
}

export function decodeEphemeralPayload(data: Uint8Array): DecodedEphemeral | null {
  if (data.length < HEADER_LEN) return null
  const messageType = data[0]
  const sessionId = data.slice(1, 1 + SESSION_ID_LEN)
  const counter = new DataView(data.buffer, data.byteOffset).getUint32(1 + SESSION_ID_LEN, true)
  const payload = data.slice(HEADER_LEN)
  return { messageType, sessionId, counter, payload }
}

// =============================================================================
// Session proof
// =============================================================================

/**
 * Build and sign a session proof.
 *
 * Proof format: Ed25519 signature over
 *   prefix || JCS({ localSessionId, remoteSessionId })
 * where prefix = "refmd_ephemeral_session_proof"
 */
export function buildSessionProof(
  remoteSessionId: Uint8Array,
  localSessionId: Uint8Array,
  signingPrivateKey: Uint8Array,
): Uint8Array {
  const message = buildSessionProofMessage(remoteSessionId, localSessionId)
  return ed25519.sign(message, signingPrivateKey)
}

export function verifySessionProof(
  remoteSessionId: Uint8Array,
  localSessionId: Uint8Array,
  signature: Uint8Array,
  signingPubKey: Uint8Array,
): boolean {
  const message = buildSessionProofMessage(remoteSessionId, localSessionId)
  return ed25519.verify(signature, message, signingPubKey)
}

function buildSessionProofMessage(
  remoteSessionId: Uint8Array,
  localSessionId: Uint8Array,
): Uint8Array {
  const prefix = new TextEncoder().encode(WS_SIGNATURE_PREFIX.EPHEMERAL_SESSION_PROOF)
  const payload = canonicalizeBytes({
    localSessionId: base64UrlEncode(localSessionId),
    remoteSessionId: base64UrlEncode(remoteSessionId),
  })
  const result = new Uint8Array(prefix.length + payload.length)
  result.set(prefix)
  result.set(payload, prefix.length)
  return result
}

// =============================================================================
// Incoming message handler
// =============================================================================

/**
 * Handle an incoming ephemeral message after decryption + decode.
 *
 * @param session      Local ephemeral session
 * @param decoded      Decoded ephemeral payload
 * @param senderPubKeyB64 Sender's signing public key (base64url, from envelope publicData)
 * @param senderPubKeyBytes Sender's signing public key (raw bytes, for proof verification)
 * @param localPrivKey   Local device signing private key
 */
export function handleIncomingEphemeral(
  session: EphemeralSession,
  decoded: DecodedEphemeral,
  senderPubKeyB64: string,
  senderPubKeyBytes: Uint8Array,
  localPrivKey: Uint8Array,
): EphemeralAction {
  const remoteSessionIdB64 = base64UrlEncode(decoded.sessionId)

  switch (decoded.messageType) {
    case MSG_INITIALIZE: {
      const existingInitPeer = session.trustedPeers.get(remoteSessionIdB64)
      if (existingInitPeer) {
        // Reject session ID reuse with a different signing key (anti-hijack)
        if (existingInitPeer.signingPubKey !== senderPubKeyB64) {
          return { action: 'reject', reason: 'initialize signing key mismatch for existing session' }
        }
        // Reject replay if counter is not advancing
        if (decoded.counter <= existingInitPeer.lastCounter) {
          return { action: 'reject', reason: `replay: initialize counter ${decoded.counter} <= ${existingInitPeer.lastCounter}` }
        }
      }
      // Advance lastCounter for existing trusted peer (prevents replay of this
      // initialize counter even though the peer is re-handshaking)
      if (existingInitPeer) {
        existingInitPeer.lastCounter = decoded.counter
      }
      // Reject session ID reuse in pending state with a different signing key.
      // Prevents a malicious member from hijacking another member's session ID
      // by broadcasting an initialize with the same sessionId but their own key.
      const existingPending = session.pendingInitializes.get(remoteSessionIdB64)
      if (existingPending && existingPending.signingPubKey !== senderPubKeyB64) {
        return { action: 'reject', reason: 'initialize signing key mismatch for pending session' }
      }
      // Reject replay for pending sessions (counter must strictly increase)
      if (existingPending && decoded.counter <= existingPending.lastCounter) {
        return { action: 'reject', reason: `replay: initialize counter ${decoded.counter} <= ${existingPending.lastCounter} (pending)` }
      }
      // Enforce pending map size cap (evict oldest to avoid permanent saturation)
      if (!existingPending && session.pendingInitializes.size >= MAX_PENDING) {
        evictOldestPending(session.pendingInitializes)
      }
      // Remote peer starts handshake → respond with proofAndRequestProof
      const proof = buildSessionProof(
        decoded.sessionId,
        session.sessionId,
        localPrivKey,
      )
      session.pendingInitializes.set(remoteSessionIdB64, {
        signingPubKey: senderPubKeyB64,
        lastCounter: decoded.counter,
      })
      const response = encodeEphemeralPayload(session, MSG_PROOF_AND_REQUEST, proof)
      return { action: 'respond', responsePayload: response }
    }

    case MSG_PROOF_AND_REQUEST: {
      // Remote peer responds to our initialize with proof + requests our proof.
      // We must have broadcast an initialize first (3-step handshake order).
      if (!session.initializeSent) {
        return { action: 'reject', reason: 'unexpected proofAndRequest (no initialize sent)' }
      }
      // Reject if the claimed sessionId is already bound to a different key
      // (in pending or trusted state). Prevents a malicious member from claiming
      // another peer's sessionId via a forged proofAndRequestProof header.
      const pendingBinding = session.pendingInitializes.get(remoteSessionIdB64)
      if (pendingBinding) {
        if (pendingBinding.signingPubKey !== senderPubKeyB64) {
          return { action: 'reject', reason: 'proofAndRequest sessionId bound to different key in pending' }
        }
        // Enforce counter monotonicity across message types from the same session
        if (decoded.counter <= pendingBinding.lastCounter) {
          return { action: 'reject', reason: `replay: proofAndRequest counter ${decoded.counter} <= ${pendingBinding.lastCounter} (pending)` }
        }
      }
      const existingPeer = session.trustedPeers.get(remoteSessionIdB64)
      if (existingPeer) {
        // Reject if signing key changed (session ID reuse with different key)
        if (existingPeer.signingPubKey !== senderPubKeyB64) {
          return { action: 'reject', reason: 'proofAndRequest signing key mismatch for existing session' }
        }
        // Reject replay if counter is not advancing
        if (decoded.counter <= existingPeer.lastCounter) {
          return { action: 'reject', reason: `replay: proofAndRequest counter ${decoded.counter} <= ${existingPeer.lastCounter}` }
        }
      }
      if (decoded.payload.length !== 64) {
        return { action: 'reject', reason: 'proofAndRequest payload length mismatch' }
      }
      const proofSig = decoded.payload

      // Verify: remote signed (remoteSessionId=ours, localSessionId=theirs)
      const valid = verifySessionProof(
        session.sessionId,   // our sessionId is "remote" from their perspective
        decoded.sessionId,   // their sessionId is "local" from their perspective
        proofSig,
        senderPubKeyBytes,
      )
      if (!valid) {
        return { action: 'reject', reason: 'proofAndRequest signature invalid' }
      }

      // Enforce trusted peers size cap (evict oldest to avoid permanent saturation)
      if (!existingPeer && session.trustedPeers.size >= MAX_PEERS) {
        evictOldestTrusted(session.trustedPeers)
      }

      // Add/update as trusted (counter is guaranteed to advance if already trusted)
      session.trustedPeers.set(remoteSessionIdB64, {
        lastCounter: decoded.counter,
        signingPubKey: senderPubKeyB64,
      })
      // Send our proof back
      const ourProof = buildSessionProof(
        decoded.sessionId,
        session.sessionId,
        localPrivKey,
      )
      const response = encodeEphemeralPayload(session, MSG_PROOF, ourProof)
      return { action: 'respond', responsePayload: response }
    }

    case MSG_PROOF: {
      // Remote peer completes handshake with their proof
      const pendingPeer = session.pendingInitializes.get(remoteSessionIdB64)
      if (!pendingPeer) {
        return { action: 'reject', reason: 'unexpected proof (no pending initialize)' }
      }
      // Verify the proof comes from the same key that sent the initialize
      if (pendingPeer.signingPubKey !== senderPubKeyB64) {
        return { action: 'reject', reason: 'proof sender key mismatch (possible hijack)' }
      }
      // Reject replay for pending sessions (counter must strictly increase)
      if (decoded.counter <= pendingPeer.lastCounter) {
        return { action: 'reject', reason: `replay: proof counter ${decoded.counter} <= ${pendingPeer.lastCounter} (pending)` }
      }
      // Reject replay/hijack if already trusted
      const existingProofPeer = session.trustedPeers.get(remoteSessionIdB64)
      if (existingProofPeer) {
        if (existingProofPeer.signingPubKey !== senderPubKeyB64) {
          return { action: 'reject', reason: 'proof signing key mismatch for existing session' }
        }
      }
      if (existingProofPeer && decoded.counter <= existingProofPeer.lastCounter) {
        return { action: 'reject', reason: `replay: proof counter ${decoded.counter} <= ${existingProofPeer.lastCounter}` }
      }
      if (decoded.payload.length !== 64) {
        return { action: 'reject', reason: 'proof payload length mismatch' }
      }
      const proofSig = decoded.payload

      // Verify: remote signed (remoteSessionId=ours, localSessionId=theirs)
      const valid = verifySessionProof(
        session.sessionId,
        decoded.sessionId,
        proofSig,
        senderPubKeyBytes,
      )
      if (!valid) {
        return { action: 'reject', reason: 'proof signature invalid' }
      }

      // Enforce trusted peers size cap (evict oldest to avoid permanent saturation)
      if (!existingProofPeer && session.trustedPeers.size >= MAX_PEERS) {
        evictOldestTrusted(session.trustedPeers)
      }

      session.pendingInitializes.delete(remoteSessionIdB64)
      session.trustedPeers.set(remoteSessionIdB64, {
        lastCounter: decoded.counter,
        signingPubKey: senderPubKeyB64,
      })
      return { action: 'trusted' }
    }

    case MSG_MESSAGE: {
      // Data message (Awareness update)
      const peer = session.trustedPeers.get(remoteSessionIdB64)
      if (!peer) {
        return { action: 'reject', reason: 'message from untrusted session' }
      }
      // Verify sender identity matches the key bound during handshake
      if (peer.signingPubKey !== senderPubKeyB64) {
        return { action: 'reject', reason: 'message sender key mismatch (possible impersonation)' }
      }
      // Replay prevention: counter must strictly increase
      if (decoded.counter <= peer.lastCounter) {
        return { action: 'reject', reason: `replay: counter ${decoded.counter} <= ${peer.lastCounter}` }
      }
      peer.lastCounter = decoded.counter
      return { action: 'awareness', awarenessData: decoded.payload }
    }

    default:
      return { action: 'reject', reason: `unknown messageType ${decoded.messageType}` }
  }
}
