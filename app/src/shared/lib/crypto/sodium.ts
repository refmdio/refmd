/**
 * libsodium initialization wrapper
 *
 * Provides a singleton pattern for libsodium initialization.
 * All crypto modules should use getSodium() to ensure libsodium is ready.
 *
 * Note: Uses standard libsodium-wrappers (not sumo) to reduce bundle size.
 * The standard version includes all APIs used by this application.
 */

import _sodium from 'libsodium-wrappers'

export type Sodium = typeof _sodium

let sodiumPromise: Promise<Sodium> | null = null

/**
 * Initialize and get the libsodium instance.
 * This is safe to call multiple times - it will only initialize once.
 */
export async function getSodium(): Promise<Sodium> {
  if (!sodiumPromise) {
    sodiumPromise = _sodium.ready.then(() => _sodium)
  }
  return sodiumPromise
}

/**
 * Check if libsodium is already initialized.
 */
export function isSodiumReady(): boolean {
  return sodiumPromise !== null
}
