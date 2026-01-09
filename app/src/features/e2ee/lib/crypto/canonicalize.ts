/**
 * RFC 8785 JSON Canonicalization Scheme (JCS)
 *
 * Used for creating deterministic JSON for signature verification.
 * Compatible with backend Ed25519 signature verification.
 */

import canonicalizeLib from 'canonicalize'
import { getSodium } from './sodium'

/**
 * Canonicalize a JavaScript object to deterministic JSON string.
 * Uses RFC 8785 JSON Canonicalization Scheme.
 *
 * @param input - Object to canonicalize
 * @returns Canonicalized JSON string
 * @throws Error if canonicalization fails
 */
export function canonicalize(input: unknown): string {
  const result = canonicalizeLib(input)
  if (result === undefined) {
    throw new Error('Failed to canonicalize input')
  }
  return result
}

/**
 * Canonicalize an object and encode to Base64.
 * Used for publicData in E2EE messages.
 *
 * @param input - Object to canonicalize and encode
 * @returns Base64-encoded canonicalized JSON
 */
export async function canonicalizeAndToBase64(input: unknown): Promise<string> {
  const sodium = await getSodium()
  const canonicalized = canonicalize(input)
  return sodium.to_base64(canonicalized, sodium.base64_variants.ORIGINAL)
}

/**
 * Decode Base64 and parse as JSON.
 *
 * @param base64 - Base64-encoded JSON string
 * @returns Parsed object
 */
export async function fromBase64Json<T = unknown>(base64: string): Promise<T> {
  const sodium = await getSodium()
  const decoded = sodium.from_base64(base64, sodium.base64_variants.ORIGINAL)
  const jsonStr = new TextDecoder().decode(decoded)
  return JSON.parse(jsonStr) as T
}

/**
 * Encode Uint8Array to Base64.
 */
export async function toBase64(data: Uint8Array): Promise<string> {
  const sodium = await getSodium()
  return sodium.to_base64(data, sodium.base64_variants.ORIGINAL)
}

/**
 * Decode Base64 to Uint8Array.
 */
export async function fromBase64(base64: string): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.from_base64(base64, sodium.base64_variants.ORIGINAL)
}
