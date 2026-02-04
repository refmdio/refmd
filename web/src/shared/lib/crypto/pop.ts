/**
 * Proof of Possession (PoP) utilities
 *
 * Generates PoP headers for API requests to prove device ownership.
 * Per ADR-009, PoP uses server-issued challenges to prevent replay attacks.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { base64UrlDecode, base64UrlEncode } from './encoding'

/**
 * PoP header names (must match server constants)
 */
export const POP_CHALLENGE_HEADER = 'X-PoP-Challenge'
export const POP_SIGNATURE_HEADER = 'X-PoP-Signature'
export const POP_DEVICE_ID_HEADER = 'X-PoP-Device-Id'

/**
 * PoP headers for API requests
 */
export interface PopHeaders {
  [POP_CHALLENGE_HEADER]: string
  [POP_SIGNATURE_HEADER]: string
  [POP_DEVICE_ID_HEADER]: string
}

/**
 * Response from the pop-challenge endpoint
 */
export interface PopChallengeResponse {
  challenge: string
  expires_at: number
}

/**
 * Fetch a PoP challenge from the server
 *
 * The server generates a 32-byte random challenge and stores it for
 * one-time use verification.
 *
 * @param apiBase - API base URL
 * @param deviceId - Device UUID
 * @returns Server-issued challenge (base64url encoded)
 */
export async function fetchPopChallenge(
  apiBase: string,
  deviceId: string
): Promise<PopChallengeResponse> {
  const response = await fetch(`${apiBase}/api/auth/pop-challenge`, {
    method: 'POST',
    headers: {
      [POP_DEVICE_ID_HEADER]: deviceId,
    },
    credentials: 'include',
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(`Failed to fetch PoP challenge: ${error.error}`)
  }

  return response.json()
}

/**
 * Generate PoP headers by signing a server-issued challenge
 *
 * @param challenge - Server-issued challenge (base64url encoded)
 * @param deviceId - Device UUID
 * @param signingPrivateKey - Device Ed25519 signing private key (32 bytes)
 * @returns PoP headers to include in the request
 */
export function signPopChallenge(
  challenge: string,
  deviceId: string,
  signingPrivateKey: Uint8Array
): PopHeaders {
  // Decode challenge
  const challengeBytes = base64UrlDecode(challenge)

  // Sign challenge with device signing key
  const signature = ed25519.sign(challengeBytes, signingPrivateKey)

  return {
    [POP_CHALLENGE_HEADER]: challenge,
    [POP_SIGNATURE_HEADER]: base64UrlEncode(signature),
    [POP_DEVICE_ID_HEADER]: deviceId,
  }
}

/**
 * Get PoP headers for an API request
 *
 * Fetches a server-issued challenge and signs it with the device signing key.
 * This is the main function to use for PoP-protected requests.
 *
 * @param apiBase - API base URL
 * @param deviceId - Device UUID
 * @param signingPrivateKey - Device Ed25519 signing private key (32 bytes)
 * @returns PoP headers to include in the request
 */
export async function getPopHeaders(
  apiBase: string,
  deviceId: string,
  signingPrivateKey: Uint8Array
): Promise<PopHeaders> {
  // Fetch server-issued challenge
  const { challenge } = await fetchPopChallenge(apiBase, deviceId)

  // Sign challenge and return headers
  return signPopChallenge(challenge, deviceId, signingPrivateKey)
}
