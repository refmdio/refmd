/**
 * Ed25519 signature module for E2EE messages
 *
 * Compatible with backend implementation (api/crates/infrastructure/src/core/crypto/ed25519.rs)
 * Signature format: domain + canonicalize({ciphertext, nonce, publicData})
 */

import { getSodium } from './sodium'
import { canonicalize } from './canonicalize'

/** Ed25519 public key size (32 bytes) */
export const PUBLIC_KEY_SIZE = 32

/** Ed25519 private key size (64 bytes for libsodium's keypair format) */
export const PRIVATE_KEY_SIZE = 64

/** Ed25519 signature size (64 bytes) */
export const SIGNATURE_SIZE = 64

/** Signature domains for E2EE messages (domain separation) */
export const SIGNATURE_DOMAINS = {
  SNAPSHOT: 'refmd_snapshot',
  UPDATE: 'refmd_update',
  EPHEMERAL: 'refmd_ephemeral',
} as const

export type SignatureDomain = typeof SIGNATURE_DOMAINS[keyof typeof SIGNATURE_DOMAINS]

/** Ed25519 key pair */
export interface Ed25519KeyPair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

/** Signing message content (matches backend format) */
export interface SigningMessage {
  /** Base64-encoded ciphertext */
  ciphertext: string
  /** Base64-encoded nonce */
  nonce: string
  /** Base64-encoded canonicalized publicData */
  publicData: string
}

/**
 * Generate an Ed25519 key pair for signing.
 *
 * @returns New Ed25519 key pair
 */
export async function generateKeyPair(): Promise<Ed25519KeyPair> {
  const sodium = await getSodium()
  const keyPair = sodium.crypto_sign_keypair()
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  }
}

/**
 * Build the message bytes for signing/verification.
 * Format: domain + canonicalize({ciphertext, nonce, publicData})
 *
 * Keys are sorted alphabetically per RFC 8785:
 * {"ciphertext":"...","nonce":"...","publicData":"..."}
 *
 * @param domain - Signature domain (e.g., "refmd_update")
 * @param message - Signing message content
 * @returns Message bytes to sign
 */
export function buildSigningMessage(
  domain: SignatureDomain,
  message: SigningMessage
): Uint8Array {
  // Canonicalize with sorted keys (RFC 8785)
  const canonicalJson = canonicalize({
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    publicData: message.publicData,
  })

  // domain + canonicalized JSON
  const encoder = new TextEncoder()
  const domainBytes = encoder.encode(domain)
  const jsonBytes = encoder.encode(canonicalJson)

  const result = new Uint8Array(domainBytes.length + jsonBytes.length)
  result.set(domainBytes, 0)
  result.set(jsonBytes, domainBytes.length)

  return result
}

/**
 * Sign a message using Ed25519.
 *
 * @param privateKey - 64-byte Ed25519 private key
 * @param domain - Signature domain
 * @param message - Message content to sign
 * @returns 64-byte Ed25519 signature
 */
export async function sign(
  privateKey: Uint8Array,
  domain: SignatureDomain,
  message: SigningMessage
): Promise<Uint8Array> {
  if (privateKey.length !== PRIVATE_KEY_SIZE) {
    throw new Error(`Invalid private key length: expected ${PRIVATE_KEY_SIZE}, got ${privateKey.length}`)
  }

  const sodium = await getSodium()
  const messageBytes = buildSigningMessage(domain, message)

  return sodium.crypto_sign_detached(messageBytes, privateKey)
}

/**
 * Verify an Ed25519 signature.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param signature - 64-byte Ed25519 signature
 * @param domain - Signature domain
 * @param message - Message content that was signed
 * @returns true if signature is valid, false otherwise
 */
export async function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  domain: SignatureDomain,
  message: SigningMessage
): Promise<boolean> {
  if (publicKey.length !== PUBLIC_KEY_SIZE) {
    throw new Error(`Invalid public key length: expected ${PUBLIC_KEY_SIZE}, got ${publicKey.length}`)
  }
  if (signature.length !== SIGNATURE_SIZE) {
    throw new Error(`Invalid signature length: expected ${SIGNATURE_SIZE}, got ${signature.length}`)
  }

  const sodium = await getSodium()
  const messageBytes = buildSigningMessage(domain, message)

  return sodium.crypto_sign_verify_detached(signature, messageBytes, publicKey)
}

/**
 * Sign a message and return Base64-encoded signature.
 *
 * @param privateKey - 64-byte Ed25519 private key
 * @param domain - Signature domain
 * @param message - Message content to sign
 * @returns Base64-encoded signature
 */
export async function signToBase64(
  privateKey: Uint8Array,
  domain: SignatureDomain,
  message: SigningMessage
): Promise<string> {
  const sodium = await getSodium()
  const signature = await sign(privateKey, domain, message)
  return sodium.to_base64(signature, sodium.base64_variants.ORIGINAL)
}

/**
 * Verify a Base64-encoded Ed25519 signature.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param signatureBase64 - Base64-encoded signature
 * @param domain - Signature domain
 * @param message - Message content that was signed
 * @returns true if signature is valid, false otherwise
 */
export async function verifyFromBase64(
  publicKey: Uint8Array,
  signatureBase64: string,
  domain: SignatureDomain,
  message: SigningMessage
): Promise<boolean> {
  const sodium = await getSodium()
  const signature = sodium.from_base64(signatureBase64, sodium.base64_variants.ORIGINAL)
  return verify(publicKey, signature, domain, message)
}
