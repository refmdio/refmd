/**
 * Key Fingerprint Module
 *
 * Provides fingerprint calculation for public keys using BLAKE3.
 * Used for TOFU (Trust On First Use) key verification.
 *
 * Fingerprint format:
 * - BLAKE3 hash of signing public key
 * - Truncated to 128 bits (16 bytes)
 * - Encoded as base64url (22 characters)
 * - UI display: 4-character groups separated by spaces
 */

import { blake3 } from '@noble/hashes/blake3.js'
import { base64UrlEncode } from './encoding'

/**
 * Calculate fingerprint of a signing public key
 *
 * @param signingPublicKey Ed25519 public key (32 bytes)
 * @returns Base64url encoded fingerprint (22 characters)
 */
export function calculateFingerprint(signingPublicKey: Uint8Array): string {
  if (signingPublicKey.length !== 32) {
    throw new Error('Signing public key must be 32 bytes')
  }

  // BLAKE3 hash with 128-bit (16 byte) output
  const hash = blake3(signingPublicKey, { dkLen: 16 })

  // Encode as base64url (without padding)
  return base64UrlEncode(hash)
}

/**
 * Format fingerprint for UI display
 *
 * Groups characters in 4-character chunks separated by spaces.
 * Example: "XXXX XXXX XXXX XXXX XXXX XX"
 *
 * @param fingerprint Base64url encoded fingerprint
 * @returns Formatted fingerprint string
 */
export function formatFingerprint(fingerprint: string): string {
  // Split into 4-character groups
  const groups: string[] = []
  for (let i = 0; i < fingerprint.length; i += 4) {
    groups.push(fingerprint.slice(i, i + 4))
  }
  return groups.join(' ')
}


