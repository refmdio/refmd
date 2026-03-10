import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "./encoding";
import { buildIdentityEcdhAad, buildIdentitySigningAad } from "./aad";
import { isValidX25519PublicKey } from "./key-validation";

export interface IdentityKeyPair {
  ecdhPrivate: Uint8Array;
  ecdhPublic: Uint8Array;
  signingPrivate: Uint8Array;
  signingPublic: Uint8Array;
}

export interface EncryptedIdentityKeys {
  encryptedEcdhPrivate: Uint8Array;
  ecdhPrivateNonce: Uint8Array;
  encryptedSigningPrivate: Uint8Array;
  signingPrivateNonce: Uint8Array;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const ecdhPrivate = randomBytes(32);
  const signingPrivate = randomBytes(32);
  return {
    ecdhPrivate,
    ecdhPublic: x25519.getPublicKey(ecdhPrivate),
    signingPrivate,
    signingPublic: ed25519.getPublicKey(signingPrivate),
  };
}

export function encryptIdentityKeys(
  keyPair: IdentityKeyPair,
  umk: Uint8Array,
  userId: string,
): EncryptedIdentityKeys {
  const ecdhNonce = randomBytes(24);
  const signingNonce = randomBytes(24);

  const ecdhCipher = xchacha20poly1305(umk, ecdhNonce, buildIdentityEcdhAad(userId));
  const signingCipher = xchacha20poly1305(umk, signingNonce, buildIdentitySigningAad(userId));

  return {
    encryptedEcdhPrivate: ecdhCipher.encrypt(keyPair.ecdhPrivate),
    ecdhPrivateNonce: ecdhNonce,
    encryptedSigningPrivate: signingCipher.encrypt(keyPair.signingPrivate),
    signingPrivateNonce: signingNonce,
  };
}

export function decryptIdentityPrivateKeys(
  encrypted: EncryptedIdentityKeys,
  umk: Uint8Array,
  userId: string,
): IdentityKeyPair {
  const ecdhCipher = xchacha20poly1305(umk, encrypted.ecdhPrivateNonce, buildIdentityEcdhAad(userId));
  const signingCipher = xchacha20poly1305(umk, encrypted.signingPrivateNonce, buildIdentitySigningAad(userId));

  const ecdhPrivate = ecdhCipher.decrypt(encrypted.encryptedEcdhPrivate);
  const signingPrivate = signingCipher.decrypt(encrypted.encryptedSigningPrivate);

  return {
    ecdhPrivate,
    ecdhPublic: x25519.getPublicKey(ecdhPrivate),
    signingPrivate,
    signingPublic: ed25519.getPublicKey(signingPrivate),
  };
}

export function sign(message: Uint8Array, signingPrivate: Uint8Array): Uint8Array {
  return ed25519.sign(message, signingPrivate);
}

export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  signingPublic: Uint8Array,
): boolean {
  return ed25519.verify(signature, message, signingPublic);
}

export function ecdhSharedSecret(
  myPrivate: Uint8Array,
  theirPublic: Uint8Array,
): Uint8Array {
  if (!isValidX25519PublicKey(theirPublic)) {
    throw new Error("Invalid X25519 public key: low-order point");
  }
  const shared = x25519.getSharedSecret(myPrivate, theirPublic);
  if (shared.every((b) => b === 0)) {
    throw new Error("Invalid ECDH: all-zero shared secret");
  }
  return shared;
}
