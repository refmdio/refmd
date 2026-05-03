import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { buildShareDekWrapAad } from "./aad";
import { randomBytes } from "./encoding";

const shareDekEncryptionKeys = new Map<string, Uint8Array>();

export function setShareDekEncryptionKey(shareSlug: string, key: Uint8Array): void {
  shareDekEncryptionKeys.set(shareSlug, new Uint8Array(key));
}

export function getShareDekEncryptionKey(shareSlug: string): Uint8Array | null {
  const key = shareDekEncryptionKeys.get(shareSlug);
  return key ? new Uint8Array(key) : null;
}

export function clearShareDekEncryptionKey(shareSlug?: string): void {
  if (shareSlug) {
    shareDekEncryptionKeys.delete(shareSlug);
    return;
  }

  shareDekEncryptionKeys.clear();
}

export function unwrapShareDek(params: {
  encryptedDek: Uint8Array;
  nonce: Uint8Array;
  dekEncryptionKey: Uint8Array;
  shareId: string;
  documentId: string;
}): Uint8Array {
  const aad = buildShareDekWrapAad(params.shareId, params.documentId);
  const cipher = xchacha20poly1305(params.dekEncryptionKey, params.nonce, aad);
  return cipher.decrypt(params.encryptedDek);
}

export function wrapShareDek(params: {
  dek: Uint8Array;
  dekEncryptionKey: Uint8Array;
  shareId: string;
  documentId: string;
}): { encryptedDek: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const aad = buildShareDekWrapAad(params.shareId, params.documentId);
  const cipher = xchacha20poly1305(params.dekEncryptionKey, nonce, aad);
  return { encryptedDek: cipher.encrypt(params.dek), nonce };
}
