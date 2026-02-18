/**
 * Module-level store for PoP (Proof of Possession) data
 *
 * This store allows the API client to access device keys for PoP header generation
 * without being React-aware. The values are set from React context.
 *
 * Security note: Device keys are kept in memory only for the duration of the session.
 * They are cleared on logout.
 */

let deviceId: string | null = null
let signingPrivateKey: Uint8Array | null = null

/**
 * Set PoP credentials for API requests
 *
 * Called from React context when device state changes.
 */
export function setPopCredentials(
  id: string | null,
  privateKey: Uint8Array | null
): void {
  deviceId = id
  signingPrivateKey = privateKey ? new Uint8Array(privateKey) : null
}

/**
 * Clear PoP credentials
 *
 * Called on logout to clear sensitive data from memory.
 */
export function clearPopCredentials(): void {
  deviceId = null
  signingPrivateKey = null
}

/**
 * Get current PoP credentials
 *
 * Returns null if credentials are not available.
 */
export function getPopCredentials(): { deviceId: string; signingPrivateKey: Uint8Array } | null {
  if (!deviceId || !signingPrivateKey) {
    return null
  }
  return { deviceId, signingPrivateKey }
}
