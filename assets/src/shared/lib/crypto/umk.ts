import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "./encoding";
import { buildUmkWrapAad } from "./aad";

export function generateUmk(): Uint8Array {
  return randomBytes(32);
}

export function wrapUmk(
  umk: Uint8Array,
  puk: Uint8Array,
  userId: string,
): { encryptedUmk: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const aad = buildUmkWrapAad(userId);
  const cipher = xchacha20poly1305(puk, nonce, aad);
  return { encryptedUmk: cipher.encrypt(umk), nonce };
}

export function unwrapUmk(
  encryptedUmk: Uint8Array,
  nonce: Uint8Array,
  puk: Uint8Array,
  userId: string,
): Uint8Array {
  const aad = buildUmkWrapAad(userId);
  const cipher = xchacha20poly1305(puk, nonce, aad);
  return cipher.decrypt(encryptedUmk);
}
