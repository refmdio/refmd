/**
 * Ephemeral Session Proof Exchange
 *
 * Implements a 3-message handshake for anti-impersonation:
 *   1. initialize:           A -> B  (sessionIdA, no proof)
 *   2. proofAndRequestProof: B -> A  (sessionIdB, proofB->A)
 *   3. proof:                A -> B  (sessionIdA, proofA->B)
 *
 * After the handshake, both peers are mutually trusted and can exchange
 * `message` type payloads (e.g. Awareness updates) with replay prevention
 * via a per-session monotonic counter.
 *
 * Binary format of decrypted ephemeral content:
 *   [1B type][24B sessionId][4B counter LE][payload]
 */
import { randomBytes, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import type { CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
// =============================================================================
// Constants
// =============================================================================
export const MSG_INITIALIZE = 1;
const MSG_PROOF_AND_REQUEST = 2;
const MSG_PROOF = 3;
export const MSG_MESSAGE = 4;
const SESSION_PROOF_PREFIX = "refmd_ephemeral_session_proof";
const SESSION_ID_LEN = 24;
const COUNTER_LEN = 4;
const HEADER_LEN = 1 + SESSION_ID_LEN + COUNTER_LEN; // 29
const MAX_PEERS = 256;
const MAX_PENDING = 256;
// =============================================================================
// Types
// =============================================================================
interface TrustedPeer {
  lastCounter: number;
  signingPubKey: string; // base64url
}
interface PendingPeer {
  signingPubKey: string; // base64url
  lastCounter: number;
}
export interface EphemeralSession {
  sessionId: Uint8Array; // 24 bytes random
  sessionCounter: number; // monotonic outbound counter
  trustedPeers: Map<string, TrustedPeer>;
  pendingInitializes: Map<string, PendingPeer>;
  initializeSent: boolean;
}
interface DecodedEphemeral {
  messageType: number;
  sessionId: Uint8Array;
  counter: number;
  payload: Uint8Array;
}
type EphemeralAction =
  | {
      action: "respond";
      responsePayload: Uint8Array;
    }
  | {
      action: "trusted";
      awarenessData?: undefined;
    }
  | {
      action: "awareness";
      awarenessData: Uint8Array;
    }
  | {
      action: "reject";
      reason: string;
    };
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
  };
}
function evictOldestTrusted(map: Map<string, TrustedPeer>): void {
  let oldestKey: string | undefined;
  let oldestCounter = Infinity;
  for (const [key, peer] of map) {
    if (peer.lastCounter < oldestCounter) {
      oldestCounter = peer.lastCounter;
      oldestKey = key;
    }
  }
  if (oldestKey) map.delete(oldestKey);
}
function evictOldestPending(map: Map<string, PendingPeer>): void {
  let oldestKey: string | undefined;
  let oldestCounter = Infinity;
  for (const [key, peer] of map) {
    if (peer.lastCounter < oldestCounter) {
      oldestCounter = peer.lastCounter;
      oldestKey = key;
    }
  }
  if (oldestKey) map.delete(oldestKey);
}
// =============================================================================
// Encode / Decode
// =============================================================================
export function encodeEphemeralPayload(
  session: EphemeralSession,
  messageType: number,
  payload: Uint8Array,
): Uint8Array {
  const result = new Uint8Array(HEADER_LEN + payload.length);
  result[0] = messageType;
  result.set(session.sessionId, 1);
  const counter = session.sessionCounter++;
  new DataView(result.buffer, result.byteOffset).setUint32(1 + SESSION_ID_LEN, counter, true);
  result.set(payload, HEADER_LEN);
  return result;
}
export function decodeEphemeralPayload(data: Uint8Array): DecodedEphemeral | null {
  if (data.length < HEADER_LEN) return null;
  const messageType = data[0];
  const sessionId = data.slice(1, 1 + SESSION_ID_LEN);
  const counter = new DataView(data.buffer, data.byteOffset).getUint32(1 + SESSION_ID_LEN, true);
  const payload = data.slice(HEADER_LEN);
  return { messageType, sessionId, counter, payload };
}
// =============================================================================
// Incoming message handler (async — uses CryptoWorker for sign/verify)
// =============================================================================
export async function handleIncomingEphemeral(
  session: EphemeralSession,
  decoded: DecodedEphemeral,
  senderPubKeyB64: string,
  senderPubKeyBytes: Uint8Array,
  worker: CryptoWorkerClient,
): Promise<EphemeralAction> {
  const remoteSessionIdB64 = base64UrlEncode(decoded.sessionId);
  switch (decoded.messageType) {
    case MSG_INITIALIZE: {
      const existingInitPeer = session.trustedPeers.get(remoteSessionIdB64);
      if (existingInitPeer) {
        if (existingInitPeer.signingPubKey !== senderPubKeyB64) {
          return {
            action: "reject",
            reason: "initialize signing key mismatch for existing session",
          };
        }
        if (decoded.counter <= existingInitPeer.lastCounter) {
          return {
            action: "reject",
            reason: `replay: initialize counter ${decoded.counter} <= ${existingInitPeer.lastCounter}`,
          };
        }
      }
      if (existingInitPeer) {
        existingInitPeer.lastCounter = decoded.counter;
      }
      const existingPending = session.pendingInitializes.get(remoteSessionIdB64);
      if (existingPending && existingPending.signingPubKey !== senderPubKeyB64) {
        return { action: "reject", reason: "initialize signing key mismatch for pending session" };
      }
      if (existingPending && decoded.counter <= existingPending.lastCounter) {
        return {
          action: "reject",
          reason: `replay: initialize counter ${decoded.counter} <= ${existingPending.lastCounter} (pending)`,
        };
      }
      if (!existingPending && session.pendingInitializes.size >= MAX_PENDING) {
        evictOldestPending(session.pendingInitializes);
      }
      const { signature: proof } = await worker.signSessionProof({
        prefix: SESSION_PROOF_PREFIX,
        localSessionId: base64UrlEncode(session.sessionId),
        remoteSessionId: base64UrlEncode(decoded.sessionId),
      });
      session.pendingInitializes.set(remoteSessionIdB64, {
        signingPubKey: senderPubKeyB64,
        lastCounter: decoded.counter,
      });
      const response = encodeEphemeralPayload(session, MSG_PROOF_AND_REQUEST, proof);
      return { action: "respond", responsePayload: response };
    }
    case MSG_PROOF_AND_REQUEST: {
      if (!session.initializeSent) {
        return { action: "reject", reason: "unexpected proofAndRequest (no initialize sent)" };
      }
      const pendingBinding = session.pendingInitializes.get(remoteSessionIdB64);
      if (pendingBinding) {
        if (pendingBinding.signingPubKey !== senderPubKeyB64) {
          return {
            action: "reject",
            reason: "proofAndRequest sessionId bound to different key in pending",
          };
        }
        if (decoded.counter <= pendingBinding.lastCounter) {
          return {
            action: "reject",
            reason: `replay: proofAndRequest counter ${decoded.counter} <= ${pendingBinding.lastCounter} (pending)`,
          };
        }
      }
      const existingPeer = session.trustedPeers.get(remoteSessionIdB64);
      if (existingPeer) {
        if (existingPeer.signingPubKey !== senderPubKeyB64) {
          return {
            action: "reject",
            reason: "proofAndRequest signing key mismatch for existing session",
          };
        }
        if (decoded.counter <= existingPeer.lastCounter) {
          return {
            action: "reject",
            reason: `replay: proofAndRequest counter ${decoded.counter} <= ${existingPeer.lastCounter}`,
          };
        }
      }
      if (decoded.payload.length !== 64) {
        return { action: "reject", reason: "proofAndRequest payload length mismatch" };
      }
      const proofSig = decoded.payload;
      const valid = await worker.verifySessionProof({
        prefix: SESSION_PROOF_PREFIX,
        localSessionId: base64UrlEncode(decoded.sessionId),
        remoteSessionId: base64UrlEncode(session.sessionId),
        signature: proofSig,
        signingPubKey: senderPubKeyBytes,
      });
      if (!valid) {
        return { action: "reject", reason: "proofAndRequest signature invalid" };
      }
      if (!existingPeer && session.trustedPeers.size >= MAX_PEERS) {
        evictOldestTrusted(session.trustedPeers);
      }
      session.trustedPeers.set(remoteSessionIdB64, {
        lastCounter: decoded.counter,
        signingPubKey: senderPubKeyB64,
      });
      const { signature: ourProof } = await worker.signSessionProof({
        prefix: SESSION_PROOF_PREFIX,
        localSessionId: base64UrlEncode(session.sessionId),
        remoteSessionId: base64UrlEncode(decoded.sessionId),
      });
      const response = encodeEphemeralPayload(session, MSG_PROOF, ourProof);
      return { action: "respond", responsePayload: response };
    }
    case MSG_PROOF: {
      const pendingPeer = session.pendingInitializes.get(remoteSessionIdB64);
      if (!pendingPeer) {
        return { action: "reject", reason: "unexpected proof (no pending initialize)" };
      }
      if (pendingPeer.signingPubKey !== senderPubKeyB64) {
        return { action: "reject", reason: "proof sender key mismatch (possible hijack)" };
      }
      if (decoded.counter <= pendingPeer.lastCounter) {
        return {
          action: "reject",
          reason: `replay: proof counter ${decoded.counter} <= ${pendingPeer.lastCounter} (pending)`,
        };
      }
      const existingProofPeer = session.trustedPeers.get(remoteSessionIdB64);
      if (existingProofPeer) {
        if (existingProofPeer.signingPubKey !== senderPubKeyB64) {
          return { action: "reject", reason: "proof signing key mismatch for existing session" };
        }
      }
      if (existingProofPeer && decoded.counter <= existingProofPeer.lastCounter) {
        return {
          action: "reject",
          reason: `replay: proof counter ${decoded.counter} <= ${existingProofPeer.lastCounter}`,
        };
      }
      if (decoded.payload.length !== 64) {
        return { action: "reject", reason: "proof payload length mismatch" };
      }
      const proofSig = decoded.payload;
      const valid = await worker.verifySessionProof({
        prefix: SESSION_PROOF_PREFIX,
        localSessionId: base64UrlEncode(decoded.sessionId),
        remoteSessionId: base64UrlEncode(session.sessionId),
        signature: proofSig,
        signingPubKey: senderPubKeyBytes,
      });
      if (!valid) {
        return { action: "reject", reason: "proof signature invalid" };
      }
      if (!existingProofPeer && session.trustedPeers.size >= MAX_PEERS) {
        evictOldestTrusted(session.trustedPeers);
      }
      session.pendingInitializes.delete(remoteSessionIdB64);
      session.trustedPeers.set(remoteSessionIdB64, {
        lastCounter: decoded.counter,
        signingPubKey: senderPubKeyB64,
      });
      return { action: "trusted" };
    }
    case MSG_MESSAGE: {
      const peer = session.trustedPeers.get(remoteSessionIdB64);
      if (!peer) {
        return { action: "reject", reason: "message from untrusted session" };
      }
      if (peer.signingPubKey !== senderPubKeyB64) {
        return { action: "reject", reason: "message sender key mismatch (possible impersonation)" };
      }
      if (decoded.counter <= peer.lastCounter) {
        return {
          action: "reject",
          reason: `replay: counter ${decoded.counter} <= ${peer.lastCounter}`,
        };
      }
      peer.lastCounter = decoded.counter;
      return { action: "awareness", awarenessData: decoded.payload };
    }
    default:
      return { action: "reject", reason: `unknown messageType ${decoded.messageType}` };
  }
}
