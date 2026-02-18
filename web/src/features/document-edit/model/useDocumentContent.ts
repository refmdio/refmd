/**
 * Document Content Subscription Hook
 *
 * Manages content subscription and ref counting for shared Y.Doc cache.
 * Extracted from useDocumentEdit to separate content observation from
 * document initialization and save orchestration.
 */

import { useState, useEffect } from 'react'
import type * as Y from 'yjs'
import { documentCache } from '../lib/document-cache'

/**
 * Subscribe to content changes from the shared document cache.
 * Handles ref counting: destroys Y.Doc when last subscriber disconnects.
 *
 * @param documentId Document to subscribe to
 * @param yDoc Trigger — when set, the document is ready for subscription
 * @returns current text content, and isDirty flag from cache
 */
export function useDocumentContent(
  documentId: string,
  yDoc: Y.Doc | null,
  onDirtyChange?: (dirty: boolean) => void,
): string {
  const [content, setContent] = useState('')

  useEffect(() => {
    const state = documentCache.getValue(documentId)
    if (!state) return

    const listener = (newContent: string) => {
      setContent(newContent)
      onDirtyChange?.(state.isDirty)
    }

    state.contentListeners.add(listener)
    state.refCount++

    // Sync initial content
    const yText = state.yDoc.getText('content')
    setContent(yText.toString())

    return () => {
      state.contentListeners.delete(listener)
      state.refCount--
      if (state.refCount <= 0) {
        state.yDoc.destroy()
        documentCache.removeValue(documentId)
      }
    }
  }, [documentId, yDoc])

  return content
}
