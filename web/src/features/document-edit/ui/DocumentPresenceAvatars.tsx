/**
 * Document Presence Avatars
 *
 * Wrapper around PresenceAvatars that reactively reads Awareness
 * from documentCache via its subscribe mechanism.
 *
 * Subscribes to cache value changes for the given documentId so that
 * Awareness is updated when the DocumentState is set, replaced (e.g.
 * TOFU key-change invalidation), or removed.
 */

import { useState, useEffect } from 'react'
import type { Awareness } from 'y-protocols/awareness'
import { documentCache } from '../lib/document-cache'
import { PresenceAvatars } from './PresenceAvatars'

export function DocumentPresenceAvatars({ documentId }: { documentId: string }) {
  const [awareness, setAwareness] = useState<Awareness | null>(
    () => documentCache.getValue(documentId)?.awareness ?? null,
  )

  useEffect(() => {
    // Sync initial value (may have changed between render and effect)
    setAwareness(documentCache.getValue(documentId)?.awareness ?? null)

    return documentCache.subscribe(documentId, (state) => {
      setAwareness(state?.awareness ?? null)
    })
  }, [documentId])

  return <PresenceAvatars awareness={awareness} />
}
