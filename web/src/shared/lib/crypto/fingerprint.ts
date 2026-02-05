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
  return bytesToBase64Url(hash)
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

/**
 * Parse formatted fingerprint back to raw form
 *
 * Removes spaces and validates format.
 *
 * @param formatted Formatted fingerprint with spaces
 * @returns Raw base64url fingerprint
 * @throws Error if format is invalid
 */
export function parseFormattedFingerprint(formatted: string): string {
  const raw = formatted.replace(/\s+/g, '')

  // Validate base64url characters
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error('Invalid fingerprint format: contains invalid characters')
  }

  // 128 bits = 16 bytes = 22 base64url characters (no padding)
  if (raw.length !== 22) {
    throw new Error('Invalid fingerprint format: expected 22 characters')
  }

  return raw
}

/**
 * Compare two fingerprints for equality
 *
 * Accepts both raw and formatted fingerprints.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param a First fingerprint
 * @param b Second fingerprint
 * @returns true if fingerprints match
 */
export function fingerprintsEqual(a: string, b: string): boolean {
  // Normalize both fingerprints (remove spaces)
  const normalizedA = a.replace(/\s+/g, '')
  const normalizedB = b.replace(/\s+/g, '')

  if (normalizedA.length !== normalizedB.length) {
    return false
  }

  // Constant-time comparison
  let diff = 0
  for (let i = 0; i < normalizedA.length; i++) {
    diff |= normalizedA.charCodeAt(i) ^ normalizedB.charCodeAt(i)
  }

  return diff === 0
}

/**
 * Verify that a public key matches an expected fingerprint
 *
 * @param signingPublicKey Ed25519 public key to verify
 * @param expectedFingerprint Expected fingerprint (raw or formatted)
 * @returns true if the key matches the fingerprint
 */
export function verifyFingerprint(
  signingPublicKey: Uint8Array,
  expectedFingerprint: string
): boolean {
  const actualFingerprint = calculateFingerprint(signingPublicKey)
  return fingerprintsEqual(actualFingerprint, expectedFingerprint)
}

/**
 * Convert bytes to base64url string (no padding)
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join('')
  return btoa(binString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
