/**
 * Plugin DEK derivation module
 *
 * Derives a unique DEK (Data Encryption Key) for each plugin from the document DEK.
 * This ensures that each plugin has its own encryption namespace, and plugins
 * cannot access each other's encrypted data.
 */

import { deriveKey, HKDF_CONTEXTS } from '../crypto/hkdf'

/**
 * Derive a plugin-specific DEK from the document DEK.
 *
 * Uses HKDF-SHA256 with context 'refmd_pl' and a subkey ID derived from
 * the plugin ID hash to ensure each plugin gets a unique key.
 *
 * @param documentDEK - 32-byte document DEK
 * @param pluginId - Unique plugin identifier
 * @returns 32-byte plugin DEK
 */
export async function derivePluginDEK(
  documentDEK: Uint8Array,
  pluginId: string
): Promise<Uint8Array> {
  // Generate a deterministic subkey ID from plugin ID
  // Use a simple hash: sum of char codes mod 2^31
  const subkeyId = hashPluginId(pluginId)

  return deriveKey(documentDEK, subkeyId, HKDF_CONTEXTS.PLUGIN, 32)
}

/**
 * Hash plugin ID to a numeric subkey ID.
 *
 * Produces a deterministic 31-bit positive integer from the plugin ID string.
 */
function hashPluginId(pluginId: string): number {
  let hash = 0
  for (let i = 0; i < pluginId.length; i++) {
    const char = pluginId.charCodeAt(i)
    hash = ((hash << 5) - hash + char) | 0
  }
  // Ensure positive 31-bit integer
  return Math.abs(hash) & 0x7fffffff
}
