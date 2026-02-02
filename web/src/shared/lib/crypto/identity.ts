/**
 * Identity Key operations
 *
 * Each user has:
 * - Identity ECDH key pair (X25519) for key exchange
 * - Identity Signing key pair (Ed25519) for signatures
 *
 * Private keys are encrypted with UMK using XChaCha20-Poly1305
 */

import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'

/**
 * Identity key pair (ECDH + Signing)
 */
export interface IdentityKeyPair {
  /** X25519 private key (32 bytes) */
  ecdhPrivate: Uint8Array
  /** X25519 public key (32 bytes) */
  ecdhPublic: Uint8Array
  /** Ed25519 private key (32 bytes seed) */
  signingPrivate: Uint8Array
  /** Ed25519 public key (32 bytes) */
  signingPublic: Uint8Array
}

/**
 * Encrypted identity keys for storage (with public keys)
 */
export interface EncryptedIdentityKeys {
  /** Encrypted ECDH private key */
  encryptedEcdhPrivate: Uint8Array
  /** Nonce for ECDH private key encryption */
  ecdhPrivateNonce: Uint8Array
  /** Encrypted Signing private key */
  encryptedSigningPrivate: Uint8Array
  /** Nonce for Signing private key encryption */
  signingPrivateNonce: Uint8Array
  /** ECDH public key (not encrypted) */
  ecdhPublic: Uint8Array
  /** Signing public key (not encrypted) */
  signingPublic: Uint8Array
}

/**
 * Encrypted identity private keys only (for login response)
 * Public keys are derived from decrypted private keys
 */
export interface EncryptedIdentityPrivateKeys {
  /** Encrypted ECDH private key */
  encryptedEcdhPrivate: Uint8Array
  /** Nonce for ECDH private key encryption */
  ecdhPrivateNonce: Uint8Array
  /** Encrypted Signing private key */
  encryptedSigningPrivate: Uint8Array
  /** Nonce for Signing private key encryption */
  signingPrivateNonce: Uint8Array
}

/**
 * Derive public key from X25519 private key
 */
export function deriveEcdhPublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey)
}

/**
 * Derive public key from Ed25519 private key
 */
export function deriveSigningPublicKey(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey)
}

/**
 * Generate a new identity key pair
 * - ECDH: X25519 for key exchange
 * - Signing: Ed25519 for signatures
 */
export function generateIdentityKeyPair(): IdentityKeyPair {
  // Generate X25519 key pair
  const ecdhPrivate = randomBytes(32)
  const ecdhPublic = x25519.getPublicKey(ecdhPrivate)

  // Generate Ed25519 key pair
  const signingPrivate = randomBytes(32)
  const signingPublic = ed25519.getPublicKey(signingPrivate)

  return {
    ecdhPrivate,
    ecdhPublic,
    signingPrivate,
    signingPublic,
  }
}

/**
 * Encrypt identity private keys with UMK
 *
 * @param keyPair Identity key pair
 * @param umk User Master Key (32 bytes)
 * @returns Encrypted identity keys for server storage
 */
export function encryptIdentityKeys(
  keyPair: IdentityKeyPair,
  umk: Uint8Array
): EncryptedIdentityKeys {
  // Encrypt ECDH private key
  const ecdhPrivateNonce = randomBytes(24)
  const ecdhCipher = xchacha20poly1305(umk, ecdhPrivateNonce)
  const encryptedEcdhPrivate = ecdhCipher.encrypt(keyPair.ecdhPrivate)

  // Encrypt Signing private key
  const signingPrivateNonce = randomBytes(24)
  const signingCipher = xchacha20poly1305(umk, signingPrivateNonce)
  const encryptedSigningPrivate = signingCipher.encrypt(keyPair.signingPrivate)

  return {
    encryptedEcdhPrivate,
    ecdhPrivateNonce,
    encryptedSigningPrivate,
    signingPrivateNonce,
    ecdhPublic: keyPair.ecdhPublic,
    signingPublic: keyPair.signingPublic,
  }
}

/**
 * Decrypt identity private keys with UMK (public keys provided)
 *
 * @param encrypted Encrypted identity keys from server
 * @param umk User Master Key (32 bytes)
 * @returns Decrypted identity key pair
 * @throws Error if decryption fails
 */
export function decryptIdentityKeys(
  encrypted: EncryptedIdentityKeys,
  umk: Uint8Array
): IdentityKeyPair {
  // Decrypt ECDH private key
  const ecdhCipher = xchacha20poly1305(umk, encrypted.ecdhPrivateNonce)
  const ecdhPrivate = ecdhCipher.decrypt(encrypted.encryptedEcdhPrivate)

  // Decrypt Signing private key
  const signingCipher = xchacha20poly1305(umk, encrypted.signingPrivateNonce)
  const signingPrivate = signingCipher.decrypt(encrypted.encryptedSigningPrivate)

  return {
    ecdhPrivate,
    ecdhPublic: encrypted.ecdhPublic,
    signingPrivate,
    signingPublic: encrypted.signingPublic,
  }
}

/**
 * Decrypt identity private keys with UMK and derive public keys
 * Used when only encrypted private keys are available (e.g., login response)
 *
 * @param encrypted Encrypted identity private keys from server
 * @param umk User Master Key (32 bytes)
 * @returns Decrypted identity key pair with derived public keys
 * @throws Error if decryption fails
 */
export function decryptIdentityPrivateKeys(
  encrypted: EncryptedIdentityPrivateKeys,
  umk: Uint8Array
): IdentityKeyPair {
  // Decrypt ECDH private key
  const ecdhCipher = xchacha20poly1305(umk, encrypted.ecdhPrivateNonce)
  const ecdhPrivate = ecdhCipher.decrypt(encrypted.encryptedEcdhPrivate)

  // Decrypt Signing private key
  const signingCipher = xchacha20poly1305(umk, encrypted.signingPrivateNonce)
  const signingPrivate = signingCipher.decrypt(encrypted.encryptedSigningPrivate)

  // Derive public keys from private keys
  const ecdhPublic = x25519.getPublicKey(ecdhPrivate)
  const signingPublic = ed25519.getPublicKey(signingPrivate)

  return {
    ecdhPrivate,
    ecdhPublic,
    signingPrivate,
    signingPublic,
  }
}

/**
 * Sign a message with the signing key
 *
 * @param message Message to sign
 * @param signingPrivate Ed25519 private key
 * @returns Signature (64 bytes)
 */
export function sign(message: Uint8Array, signingPrivate: Uint8Array): Uint8Array {
  return ed25519.sign(message, signingPrivate)
}

/**
 * Verify a signature
 *
 * @param message Original message
 * @param signature Signature to verify
 * @param signingPublic Ed25519 public key
 * @returns true if signature is valid
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  signingPublic: Uint8Array
): boolean {
  return ed25519.verify(signature, message, signingPublic)
}

/**
 * Perform ECDH key exchange
 *
 * @param myPrivate My X25519 private key
 * @param theirPublic Their X25519 public key
 * @returns Shared secret (32 bytes)
 */
export function ecdhSharedSecret(myPrivate: Uint8Array, theirPublic: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(myPrivate, theirPublic)
}
