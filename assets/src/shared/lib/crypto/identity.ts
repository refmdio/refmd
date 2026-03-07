import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "./encoding";
import { buildIdentityEcdhAad, buildIdentitySigningAad } from "./aad";

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

const LOW_ORDER_POINTS: Uint8Array[] = [
  new Uint8Array(32), // all zeros
  new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
  new Uint8Array([0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00]),
  new Uint8Array([0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57]),
  new Uint8Array([0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
  new Uint8Array([0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
  new Uint8Array([0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
  new Uint8Array([0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
];

function isLowOrderPoint(point: Uint8Array): boolean {
  return LOW_ORDER_POINTS.some(
    (lop) => lop.length === point.length && lop.every((b: number, i: number) => b === point[i]),
  );
}

export function ecdhSharedSecret(
  myPrivate: Uint8Array,
  theirPublic: Uint8Array,
): Uint8Array {
  if (isLowOrderPoint(theirPublic)) {
    throw new Error("Invalid X25519 public key: low-order point");
  }
  const shared = x25519.getSharedSecret(myPrivate, theirPublic);
  if (shared.every((b) => b === 0)) {
    throw new Error("Invalid ECDH: all-zero shared secret");
  }
  return shared;
}
