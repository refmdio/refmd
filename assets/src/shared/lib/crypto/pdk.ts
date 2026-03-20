import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "./encoding";
import { buildPdkUmkWrapAad, buildPdkDeviceEcdhAad, buildPdkDeviceSigningAad } from "./aad";

interface PdkWrapped {
  ciphertext: string;
  nonce: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function pdkWrap(pdk: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): PdkWrapped {
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(pdk, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);
  return { ciphertext: toHex(ciphertext), nonce: toHex(nonce) };
}

function pdkUnwrap(pdk: Uint8Array, wrapped: PdkWrapped, aad: Uint8Array): Uint8Array {
  const nonce = fromHex(wrapped.nonce);
  const ciphertext = fromHex(wrapped.ciphertext);
  const cipher = xchacha20poly1305(pdk, nonce, aad);
  return cipher.decrypt(ciphertext);
}

// Pure crypto operations (no localStorage, safe for Worker)
export function pdkWrapUmk(
  pdk: Uint8Array,
  umk: Uint8Array,
  userId: string,
): { ciphertext: string; nonce: string } {
  return pdkWrap(pdk, umk, buildPdkUmkWrapAad(userId));
}

export function pdkUnwrapUmk(
  pdk: Uint8Array,
  wrapped: { ciphertext: string; nonce: string },
  userId: string,
): Uint8Array {
  return pdkUnwrap(pdk, wrapped, buildPdkUmkWrapAad(userId));
}

export function pdkWrapDeviceKeys(
  pdk: Uint8Array,
  ecdhPrivate: Uint8Array,
  signingPrivate: Uint8Array,
  userId: string,
): { ecdh: { ciphertext: string; nonce: string }; signing: { ciphertext: string; nonce: string } } {
  return {
    ecdh: pdkWrap(pdk, ecdhPrivate, buildPdkDeviceEcdhAad(userId)),
    signing: pdkWrap(pdk, signingPrivate, buildPdkDeviceSigningAad(userId)),
  };
}

export function pdkUnwrapDeviceKeys(
  pdk: Uint8Array,
  wrappedEcdh: { ciphertext: string; nonce: string },
  wrappedSigning: { ciphertext: string; nonce: string },
  userId: string,
): { ecdhPrivate: Uint8Array; signingPrivate: Uint8Array } {
  return {
    ecdhPrivate: pdkUnwrap(pdk, wrappedEcdh, buildPdkDeviceEcdhAad(userId)),
    signingPrivate: pdkUnwrap(pdk, wrappedSigning, buildPdkDeviceSigningAad(userId)),
  };
}
