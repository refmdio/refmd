/**
 * Device Key Generation
 *
 * Generates X25519 ECDH and Ed25519 signing key pairs for new devices.
 * Used during multi-device registration.
 */

import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { randomBytes } from '@noble/ciphers/utils.js'

/**
 * Device key pair for E2EE
 */
export interface DeviceKeyPair {
  /** X25519 ECDH private key (32 bytes) */
  ecdhPrivateKey: Uint8Array
  /** X25519 ECDH public key (32 bytes) */
  ecdhPublicKey: Uint8Array
  /** Ed25519 signing private key seed (32 bytes) */
  signingPrivateKey: Uint8Array
  /** Ed25519 signing public key (32 bytes) */
  signingPublicKey: Uint8Array
}

/**
 * Generate a new device key pair
 *
 * Creates:
 * - X25519 ECDH key pair for key exchange
 * - Ed25519 signing key pair for authentication
 *
 * @returns Device key pair
 */
export function generateDeviceKeyPair(): DeviceKeyPair {
  // Generate X25519 ECDH key pair
  const ecdhPrivateKey = x25519.utils.randomPrivateKey()
  const ecdhPublicKey = x25519.getPublicKey(ecdhPrivateKey)

  // Generate Ed25519 signing key pair
  const signingPrivateKey = ed25519.utils.randomPrivateKey()
  const signingPublicKey = ed25519.getPublicKey(signingPrivateKey)

  return {
    ecdhPrivateKey,
    ecdhPublicKey,
    signingPrivateKey,
    signingPublicKey,
  }
}

/**
 * Generate a client nonce for SAS
 *
 * @returns 16-byte random nonce
 */
export function generateClientNonce(): Uint8Array {
  return randomBytes(16)
}

/**
 * Sign a message with device signing key
 *
 * @param message - Message to sign
 * @param privateKey - Ed25519 private key seed
 * @returns Ed25519 signature (64 bytes)
 */
export function signWithDeviceKey(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey)
}

/**
 * Verify a signature with device signing public key
 *
 * @param message - Original message
 * @param signature - Ed25519 signature
 * @param publicKey - Ed25519 public key
 * @returns true if signature is valid
 */
export function verifyDeviceSignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey)
  } catch {
    return false
  }
}
