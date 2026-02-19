/**
 * Encoding utilities for crypto operations
 */

/**
 * Convert bytes to a binary string (safe for arbitrary-length arrays).
 * Avoids `String.fromCharCode(...spread)` which throws RangeError for large payloads.
 */
function bytesToBinaryString(bytes: Uint8Array): string {
  let result = ''
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i])
  }
  return result
}

/**
 * Encode bytes to base64url string (URL-safe, no padding)
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  const base64 = btoa(bytesToBinaryString(bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Valid base64url character pattern (no padding, no standard base64 chars) */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/

/**
 * Decode base64url string to bytes (strict mode)
 *
 * Rejects:
 * - Padding characters (=)
 * - Whitespace/newlines
 * - Standard Base64 characters (+, /)
 * - Invalid length (length % 4 == 1)
 *
 * @throws Error if input is invalid
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Reject empty strings early
  if (str.length === 0) {
    return new Uint8Array(0)
  }

  // Reject padding characters
  if (str.includes('=')) {
    throw new Error('Invalid base64url: padding not allowed')
  }

  // Reject whitespace/newlines and standard Base64 characters
  if (!BASE64URL_PATTERN.test(str)) {
    throw new Error('Invalid base64url: contains invalid characters')
  }

  // Reject invalid length (length % 4 == 1 is invalid for no-padding base64url)
  if (str.length % 4 === 1) {
    throw new Error('Invalid base64url: invalid length')
  }

  // Convert to standard base64 and add padding
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padding = (4 - (base64.length % 4)) % 4
  base64 += '='.repeat(padding)

  try {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes
  } catch {
    throw new Error('Invalid base64url: decoding failed')
  }
}

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing side-channel attacks when comparing secrets.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
}

