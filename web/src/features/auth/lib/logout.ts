/**
 * Logout Functions
 *
 * Normal and secure logout with appropriate data cleanup.
 */

import { authApi } from '@/shared/api'
import {
  clearSessionUmk,
  clearDskData,
  clearPdkWrappedDeviceKeys,
  clearPdkWrappedUmk,
  clearPdkEphemeral,
} from '@/shared/lib/crypto'
import { clearAllTofuEntries } from '@/shared/lib/trust-store'
import {
  clearAllRevocationPins,
  clearAllKeyVersionPins,
  clearAllDocumentStatePins,
} from '@/shared/lib/anti-rollback'
import { clearKekCache } from '@/entities/workspace'

/**
 * Clear volatile in-memory session state (shared by both logout paths).
 */
function clearVolatileSessionState(): void {
  clearSessionUmk()
  clearPdkEphemeral()
  clearKekCache()
}

/**
 * Logout (normal) - keeps IndexedDB cache for quick re-login
 */
export async function logout(): Promise<void> {
  clearVolatileSessionState()
  await authApi.logout()
}

/**
 * Secure logout - clears all local data including IndexedDB
 */
export async function secureLogout(): Promise<void> {
  clearVolatileSessionState()
  clearPdkWrappedDeviceKeys()
  clearPdkWrappedUmk()

  // Preventive deletion of reserved localStorage keys (per secure-logout.md)
  localStorage.removeItem('refmd-browser-fingerprint')

  await Promise.all([
    authApi.logout(),
    clearDskData(),
    clearAllTofuEntries(),
    clearAllRevocationPins(),
    clearAllKeyVersionPins(),
    clearAllDocumentStatePins(),
  ])
}
