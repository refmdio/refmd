import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "./encoding";
import { buildDekWrapAad, buildDocumentTitleAad } from "./aad";

export function generateDek(): Uint8Array {
  return randomBytes(32);
}

export function wrapDek(
  dek: Uint8Array,
  kek: Uint8Array,
  documentId: string,
  workspaceId: string,
): { encryptedDek: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const aad = buildDekWrapAad(documentId, workspaceId);
  const cipher = xchacha20poly1305(kek, nonce, aad);
  const encryptedDek = cipher.encrypt(dek);
  return { encryptedDek, nonce };
}

export function unwrapDek(
  encryptedDek: Uint8Array,
  nonce: Uint8Array,
  kek: Uint8Array,
  documentId: string,
  workspaceId: string,
): Uint8Array {
  const aad = buildDekWrapAad(documentId, workspaceId);
  const cipher = xchacha20poly1305(kek, nonce, aad);
  return cipher.decrypt(encryptedDek);
}

export function encryptTitle(
  title: string,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number,
): { encrypted: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const aad = buildDocumentTitleAad(documentId, keyVersion);
  const plaintext = new TextEncoder().encode(title);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const encrypted = cipher.encrypt(plaintext);
  return { encrypted, nonce };
}

export function decryptTitle(
  encrypted: Uint8Array,
  nonce: Uint8Array,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number,
): string {
  const aad = buildDocumentTitleAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(encrypted);
  return new TextDecoder().decode(plaintext);
}
