import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import type { CryptoErrorCode } from "../types";
import type { WorkerKeyState } from "../state";
import { CryptoOperationError } from "../operation-error";
import { getCachedDek, getCachedKek } from "../state";
export type HandlerPayload = Record<string, unknown>;
function wrapCryptoOperationError(code: CryptoErrorCode, error: unknown): CryptoOperationError {
  if (error instanceof CryptoOperationError) return error;
  const message = error instanceof Error ? error.message : "Unknown error";
  return new CryptoOperationError(code, message);
}
export async function withCryptoOperationError<T>(
  code: CryptoErrorCode,
  operation: () => T | Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw wrapCryptoOperationError(code, error);
  }
}
export function requireUmk(state: WorkerKeyState): Uint8Array {
  if (!state.umk) throw new CryptoOperationError("not_initialized", "UMK not available");
  return state.umk;
}
export function requireDeviceEcdhPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.deviceEcdhPrivate) {
    throw new CryptoOperationError("not_initialized", "Device ECDH private key not available");
  }
  return state.deviceEcdhPrivate;
}
export function requireDeviceSigningPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.deviceSigningPrivate) {
    throw new CryptoOperationError("not_initialized", "Device signing private key not available");
  }
  return state.deviceSigningPrivate;
}
export function requireIdentitySigningPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.identitySigningPrivate) {
    throw new CryptoOperationError("not_initialized", "Identity signing private key not available");
  }
  return state.identitySigningPrivate;
}
export function requireIdentityEcdhPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.identityEcdhPrivate) {
    throw new CryptoOperationError("not_initialized", "Identity ECDH private key not available");
  }
  return state.identityEcdhPrivate;
}
export function requireDsk(state: WorkerKeyState): CryptoKey {
  if (!state.dsk) throw new CryptoOperationError("not_initialized", "DSK not available");
  return state.dsk;
}
export function requireUserId(state: WorkerKeyState): string {
  if (!state.userId) throw new CryptoOperationError("not_initialized", "userId not available");
  return state.userId;
}
export function requireDeviceId(state: WorkerKeyState): string {
  if (!state.deviceId) throw new CryptoOperationError("not_initialized", "deviceId not available");
  return state.deviceId;
}
export function requireKekForWorkspace(
  state: WorkerKeyState,
  workspaceId: string,
  keyVersion?: number,
): {
  kek: Uint8Array;
  keyVersion: number;
} {
  const cached = getCachedKek(state, workspaceId, keyVersion);
  if (!cached) {
    throw new CryptoOperationError(
      "key_not_found",
      `KEK not cached for workspace ${workspaceId}${keyVersion !== undefined ? ` version ${keyVersion}` : ""}`,
    );
  }
  return cached;
}
export function requireDekForDocument(
  state: WorkerKeyState,
  documentId: string,
  keyVersion?: number,
): {
  dek: Uint8Array;
  keyVersion: number;
} {
  const cached = getCachedDek(state, documentId, keyVersion);
  if (!cached) {
    throw new CryptoOperationError(
      "key_not_found",
      `DEK not cached for document ${documentId}${keyVersion !== undefined ? ` version ${keyVersion}` : ""}`,
    );
  }
  return cached;
}
export async function dskEncrypt(
  dsk: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(aad).buffer },
    dsk,
    new Uint8Array(plaintext),
  );
  return { ciphertext, iv: iv.buffer };
}
export async function dskDecrypt(
  dsk: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: ArrayBuffer,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(aad).buffer },
    dsk,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}
export function setIdentityFromDecrypted(
  state: WorkerKeyState,
  identity: {
    ecdhPrivate: Uint8Array;
    ecdhPublic: Uint8Array;
    signingPrivate: Uint8Array;
    signingPublic: Uint8Array;
  },
): void {
  state.identityEcdhPrivate = identity.ecdhPrivate;
  state.identityEcdhPublic = identity.ecdhPublic;
  state.identitySigningPrivate = identity.signingPrivate;
  state.identitySigningPublic = identity.signingPublic;
}
export function setDeviceFromPrivateKeys(
  state: WorkerKeyState,
  ecdhPrivate: Uint8Array,
  signingPrivate: Uint8Array,
): void {
  state.deviceEcdhPrivate = ecdhPrivate;
  state.deviceEcdhPublic = x25519.getPublicKey(ecdhPrivate);
  state.deviceSigningPrivate = signingPrivate;
  state.deviceSigningPublic = ed25519.getPublicKey(signingPrivate);
}
