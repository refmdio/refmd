/**
 * KEK Cache & Deduplication
 *
 * Module-level cache for resolved KEKs and promise deduplication
 * to prevent concurrent fetch/create races (e.g. React Strict Mode).
 *
 * Exposes the DedupCache instance directly. Use kekCache.getValue(id),
 * kekCache.setValue(id, key), etc.
 */

import { createDedupCache } from '@/shared/lib/dedup-cache'

export const kekCache = createDedupCache<Uint8Array>()

/**
 * Clear the KEK cache. Must be called on logout and after KEK rotation
 * to prevent stale keys from being used.
 *
 * @param workspaceId - If provided, only clears the cache for that workspace.
 *                      Otherwise clears the entire cache.
 */
export const clearKekCache = (workspaceId?: string) => kekCache.invalidate(workspaceId)
