import type { TofuEntry } from "../trust-store";
import { SIGNATURE_ACTION, buildSignatureMessage } from "./signature";
import { ecdhEncrypt, ecdhDecrypt } from "./ecdh-cipher";
import { sign, verify } from "./identity";
import { base64UrlEncode, base64UrlDecode, constantTimeEqual } from "./encoding";
import { canonicalizeBytes, AAD_PROTOCOL, AAD_PURPOSE } from "./aad";
interface TrustStateSnapshot {
  tofuEntries: TofuEntry[];
  transferNonce: Uint8Array;
}
interface EncryptedTrustState {
  encryptedState: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
}
export interface TrustTransferAadParams {
  userId: string;
  senderDeviceId: string;
  targetDeviceId: string;
}
interface SerializedTofuEntry {
  userId: string;
  deviceId: string;
  signingPublicKey: string;
  ecdhPublicKey: string;
  firstSeenAt: number;
  lastSeenAt: number;
}
interface SerializedSnapshot {
  entries: SerializedTofuEntry[];
  transferNonce: string;
}
function serializeEntry(entry: TofuEntry): SerializedTofuEntry {
  return {
    userId: entry.userId,
    deviceId: entry.deviceId,
    signingPublicKey: base64UrlEncode(entry.signingPublicKey),
    ecdhPublicKey: base64UrlEncode(entry.ecdhPublicKey),
    firstSeenAt: entry.firstSeenAt,
    lastSeenAt: entry.lastSeenAt,
  };
}
function deserializeEntry(serialized: SerializedTofuEntry): TofuEntry {
  return {
    userId: serialized.userId,
    deviceId: serialized.deviceId,
    signingPublicKey: base64UrlDecode(serialized.signingPublicKey),
    ecdhPublicKey: base64UrlDecode(serialized.ecdhPublicKey),
    firstSeenAt: serialized.firstSeenAt,
    lastSeenAt: serialized.lastSeenAt,
  };
}
function buildTrustTransferAad(params: TrustTransferAadParams): Uint8Array {
  return canonicalizeBytes({
    ...AAD_PROTOCOL,
    purpose: AAD_PURPOSE.TRUST_STATE_TRANSFER,
    user_id: params.userId,
    sender_device_id: params.senderDeviceId,
    target_device_id: params.targetDeviceId,
  });
}
function buildTransferSignatureMessage(
  ciphertext: Uint8Array,
  transferNonce: Uint8Array,
): Uint8Array {
  return buildSignatureMessage(SIGNATURE_ACTION.TRUST_STATE_TRANSFER, {
    ciphertext: base64UrlEncode(ciphertext),
    transfer_nonce: base64UrlEncode(transferNonce),
  });
}
export function encryptTrustState(
  snapshot: TrustStateSnapshot,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  signingPrivate: Uint8Array,
  aadParams: TrustTransferAadParams,
): EncryptedTrustState {
  const serialized: SerializedSnapshot = {
    entries: snapshot.tofuEntries.map(serializeEntry),
    transferNonce: base64UrlEncode(snapshot.transferNonce),
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(serialized));
  const aad = buildTrustTransferAad(aadParams);
  const { ciphertext: encryptedState, nonce } = ecdhEncrypt(
    plaintext,
    senderEcdhPrivate,
    targetEcdhPublic,
    "trust_state_transfer",
    aad,
  );
  const signatureMessage = buildTransferSignatureMessage(encryptedState, snapshot.transferNonce);
  const signature = sign(signatureMessage, signingPrivate);
  return { encryptedState, nonce, signature };
}
export function decryptTrustState(
  encrypted: EncryptedTrustState,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  senderSigningPublic: Uint8Array,
  expectedNonce: Uint8Array,
  aadParams: TrustTransferAadParams,
): TrustStateSnapshot {
  const signatureMessage = buildTransferSignatureMessage(encrypted.encryptedState, expectedNonce);
  if (!verify(signatureMessage, encrypted.signature, senderSigningPublic)) {
    throw new Error("Trust state signature verification failed");
  }
  const aad = buildTrustTransferAad(aadParams);
  const plaintext = ecdhDecrypt(
    encrypted.encryptedState,
    encrypted.nonce,
    receiverEcdhPrivate,
    senderEcdhPublic,
    "trust_state_transfer",
    aad,
  );
  const json = new TextDecoder().decode(plaintext);
  const serialized: SerializedSnapshot = JSON.parse(json);
  const receivedNonce = base64UrlDecode(serialized.transferNonce);
  if (!constantTimeEqual(receivedNonce, expectedNonce)) {
    throw new Error("Transfer nonce mismatch");
  }
  return {
    tofuEntries: serialized.entries.map(deserializeEntry),
    transferNonce: receivedNonce,
  };
}
