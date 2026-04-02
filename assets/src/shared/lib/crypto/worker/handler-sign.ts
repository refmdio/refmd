import { blake3 } from "@noble/hashes/blake3.js";
import type { WorkerKeyState } from "./state";
import { base64UrlEncode } from "../encoding";
import { canonicalizeBytes } from "../aad";
import {
  verifyDeviceIdentitySignature,
  signDeviceApproval,
  signDeviceRegistration,
} from "../device";
import { calculateFingerprint, formatFingerprint } from "../fingerprint";
import { sign, verify } from "../identity";
import { computeSas } from "../sas";
import { buildSignatureMessage, SIGNATURE_ACTION } from "../signature";
import {
  type HandlerPayload,
  requireDeviceSigningPrivate,
  requireIdentitySigningPrivate,
} from "./handler-utils";

export function handleSignPop(state: WorkerKeyState, p: HandlerPayload): unknown {
  const challenge = p.challenge as string;
  const deviceId = p.deviceId as string;
  const signingPrivate = requireDeviceSigningPrivate(state);

  const message = buildSignatureMessage(SIGNATURE_ACTION.POP_CHALLENGE, {
    challenge,
    device_id: deviceId,
  });
  return { signature: sign(message, signingPrivate) };
}

function buildWsSignatureMessage(
  prefix: string,
  nonce: string,
  ciphertext: string,
  publicData: Record<string, unknown>,
): Uint8Array {
  const publicDataJcs = canonicalizeBytes(publicData);
  const publicDataB64 = base64UrlEncode(publicDataJcs);
  const body = canonicalizeBytes({ nonce, ciphertext, publicData: publicDataB64 });
  const prefixBytes = new TextEncoder().encode(prefix);
  const result = new Uint8Array(prefixBytes.length + body.length);
  result.set(prefixBytes);
  result.set(body, prefixBytes.length);
  return result;
}

function buildSessionProofMessage(
  prefix: string,
  localSessionId: string,
  remoteSessionId: string,
): Uint8Array {
  const prefixBytes = new TextEncoder().encode(prefix);
  const body = canonicalizeBytes({ localSessionId, remoteSessionId });
  const result = new Uint8Array(prefixBytes.length + body.length);
  result.set(prefixBytes);
  result.set(body, prefixBytes.length);
  return result;
}

export function handleSignWsEnvelope(state: WorkerKeyState, p: HandlerPayload): unknown {
  const prefix = p.prefix as string;
  const ciphertext = p.ciphertext as string;
  const nonce = p.nonce as string;
  const publicData = p.publicData as Record<string, unknown>;
  const signingPrivate = requireDeviceSigningPrivate(state);

  const message = buildWsSignatureMessage(prefix, nonce, ciphertext, publicData);
  return { signature: sign(message, signingPrivate) };
}

export function handleSignMessage(state: WorkerKeyState, p: HandlerPayload): unknown {
  const action = p.action as string;
  const payload = p.payload as Record<string, unknown>;

  const identityActions: Set<string> = new Set([
    SIGNATURE_ACTION.DEVICE_APPROVAL,
    SIGNATURE_ACTION.DEVICE_REGISTRATION,
    SIGNATURE_ACTION.DEVICE_REVOCATION,
  ]);

  const signingPrivate = identityActions.has(action)
    ? requireIdentitySigningPrivate(state)
    : requireDeviceSigningPrivate(state);

  const message = buildSignatureMessage(action, payload);
  return { signature: sign(message, signingPrivate) };
}

export function handleSignDeviceApproval(state: WorkerKeyState, p: HandlerPayload): unknown {
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;
  const identitySigningPrivate = requireIdentitySigningPrivate(state);

  const signature = signDeviceApproval(
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
    identitySigningPrivate,
  );
  return { signature };
}

export function handleSignDeviceRegistration(state: WorkerKeyState, p: HandlerPayload): unknown {
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;
  const identitySigningPrivate = requireIdentitySigningPrivate(state);

  const signature = signDeviceRegistration(
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
    identitySigningPrivate,
  );
  return { signature };
}

export function handleSignRecoveryChallenge(state: WorkerKeyState, p: HandlerPayload): unknown {
  const message = p.message as Uint8Array;
  const identitySigningPrivate = requireIdentitySigningPrivate(state);
  return { signature: sign(message, identitySigningPrivate) };
}

export function handleSignSessionProof(state: WorkerKeyState, p: HandlerPayload): unknown {
  const prefix = p.prefix as string;
  const localSessionId = p.localSessionId as string;
  const remoteSessionId = p.remoteSessionId as string;
  const signingPrivate = requireDeviceSigningPrivate(state);

  const message = buildSessionProofMessage(prefix, localSessionId, remoteSessionId);
  return { signature: sign(message, signingPrivate) };
}

export function handleVerifySessionProof(p: HandlerPayload): unknown {
  const prefix = p.prefix as string;
  const localSessionId = p.localSessionId as string;
  const remoteSessionId = p.remoteSessionId as string;
  const signature = p.signature as Uint8Array;
  const signingPubKey = p.signingPubKey as Uint8Array;

  const message = buildSessionProofMessage(prefix, localSessionId, remoteSessionId);

  try {
    return { valid: verify(message, signature, signingPubKey) };
  } catch {
    return { valid: false };
  }
}

export function handleVerifyWsSignature(p: HandlerPayload): unknown {
  const prefix = p.prefix as string;
  const ciphertext = p.ciphertext as string;
  const nonce = p.nonce as string;
  const publicData = p.publicData as Record<string, unknown>;
  const signature = p.signature as Uint8Array;
  const signingPubKey = p.signingPubKey as Uint8Array;

  const message = buildWsSignatureMessage(prefix, nonce, ciphertext, publicData);

  try {
    return { valid: verify(message, signature, signingPubKey) };
  } catch {
    return { valid: false };
  }
}

export function handleVerifyEd25519(p: HandlerPayload): unknown {
  const message = p.message as Uint8Array;
  const signature = p.signature as Uint8Array;
  const publicKey = p.publicKey as Uint8Array;

  try {
    return { valid: verify(message, signature, publicKey) };
  } catch {
    return { valid: false };
  }
}

export function handleVerifyDeviceIdentitySignature(p: HandlerPayload): unknown {
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;
  const identitySignature = p.identitySignature as Uint8Array;
  const identitySigningPublic = p.identitySigningPublic as Uint8Array;

  const valid = verifyDeviceIdentitySignature(
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
    identitySignature,
    identitySigningPublic,
  );
  return { valid };
}

export function handleComputeUpdateHash(p: HandlerPayload): unknown {
  const bytes = canonicalizeBytes(p);
  const hash = blake3(bytes);
  return { hash: base64UrlEncode(hash) };
}

export function handleComputeSnapshotProof(p: HandlerPayload): unknown {
  const ciphertextHash = p.ciphertextHash as string;
  const parentProof = p.parentProof as string;
  const snapshotId = p.snapshotId as string;

  const input = canonicalizeBytes({
    ciphertext_hash: ciphertextHash,
    parent_proof: parentProof,
    snapshot_id: snapshotId,
  });
  return { proof: base64UrlEncode(blake3(input)) };
}

export function handleBlake3Hash(p: HandlerPayload): unknown {
  const data = p.data as Uint8Array;
  return blake3(data);
}

export function handleComputeSas(p: HandlerPayload): unknown {
  const identitySigningPublic = p.identitySigningPublic as Uint8Array;
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;

  const result = computeSas(
    identitySigningPublic,
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
  );
  return {
    emojis: result.emojis.map((emoji) => ({ emoji, name: "" })),
    hash: result.bytes,
  };
}

export function handleCalculateFingerprint(p: HandlerPayload): unknown {
  const signingPublicKey = p.signingPublicKey as Uint8Array;
  const raw = calculateFingerprint(signingPublicKey);
  return { fingerprint: formatFingerprint(raw) };
}
