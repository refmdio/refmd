import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "./encoding";
import { ecdhSharedSecret } from "./identity";

const HKDF_ZERO_SALT = new Uint8Array(32);

export function ecdhEncrypt(
  plaintext: Uint8Array,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  hkdfInfo: string,
  aad: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const shared = ecdhSharedSecret(senderEcdhPrivate, targetEcdhPublic);
  const enc = new TextEncoder();
  const encryptionKey = hkdf(sha256, shared, HKDF_ZERO_SALT, enc.encode(hkdfInfo), 32);
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(encryptionKey, nonce, aad);
  return { ciphertext: cipher.encrypt(plaintext), nonce };
}

export function ecdhDecrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  hkdfInfo: string,
  aad: Uint8Array,
): Uint8Array {
  const shared = ecdhSharedSecret(receiverEcdhPrivate, senderEcdhPublic);
  const enc = new TextEncoder();
  const encryptionKey = hkdf(sha256, shared, HKDF_ZERO_SALT, enc.encode(hkdfInfo), 32);
  const cipher = xchacha20poly1305(encryptionKey, nonce, aad);
  return cipher.decrypt(ciphertext);
}
