/**
 * Encoding utilities for crypto operations
 */

/**
 * Encode bytes to base64url string (URL-safe, no padding)
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Valid base64url character pattern (no padding, no standard base64 chars) */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/

/**
 * Decode base64url string to bytes (strict mode per spec)
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
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return bytes
}

/**
 * Encode bytes to standard base64 string
 */
export function base64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

/**
 * Decode standard base64 string to bytes
 */
export function base64Decode(str: string): Uint8Array {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
