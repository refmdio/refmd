/**
 * Document Cache
 *
 * Centralized access to the shared document state cache and initialization
 * promise map. Exposes the DedupCache instance directly. All document state
 * reads/writes go through this module to keep mutable global state contained.
 */

import { createDedupCache } from '@/shared/lib/dedup-cache'
import type { DocumentState } from './types'

export const documentCache = createDedupCache<DocumentState, DocumentState | null>()

/** Remove both cached state and pending init promise (e.g. on TOFU retry). */
export const invalidateDocument = (documentId: string) => documentCache.invalidate(documentId)
