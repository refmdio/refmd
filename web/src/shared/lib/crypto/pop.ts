/**
 * Proof of Possession (PoP) utilities
 *
 * Generates PoP headers for API requests to prove device ownership.
 * Per ADR-009, PoP prevents session token theft from granting access to E2EE keys.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { base64UrlEncode } from './encoding'

/**
 * PoP header names (must match server constants)
 */
export const POP_NONCE_HEADER = 'X-PoP-Nonce'
export const POP_SIGNATURE_HEADER = 'X-PoP-Signature'
export const POP_DEVICE_ID_HEADER = 'X-PoP-Device-Id'

/**
 * PoP headers for API requests
 */
export interface PopHeaders {
  [POP_NONCE_HEADER]: string
  [POP_SIGNATURE_HEADER]: string
  [POP_DEVICE_ID_HEADER]: string
}

/**
 * Generate PoP headers for an API request
 *
 * Creates a 32-byte random nonce, signs it with the device signing key,
 * and returns the headers needed for PoP verification.
 *
 * @param deviceId - Device UUID
 * @param signingPrivateKey - Device Ed25519 signing private key (32 bytes)
 * @returns PoP headers to include in the request
 */
export function generatePopHeaders(
  deviceId: string,
  signingPrivateKey: Uint8Array
): PopHeaders {
  // Generate 32-byte random nonce
  const nonce = randomBytes(32)

  // Sign nonce with device signing key
  const signature = ed25519.sign(nonce, signingPrivateKey)

  return {
    [POP_NONCE_HEADER]: base64UrlEncode(nonce),
    [POP_SIGNATURE_HEADER]: base64UrlEncode(signature),
    [POP_DEVICE_ID_HEADER]: deviceId,
  }
}
