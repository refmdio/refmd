/**
 * Document Y.Doc Initialization Hook
 *
 * Handles Y.Doc initialization with deduplication via document-cache.
 * Depends on document metadata and KEK being available.
 * Extracted from useDocumentEdit to isolate init concerns.
 */

import { useState, useEffect } from 'react'
import * as Y from 'yjs'
import type { DocumentResponse } from '@/shared/api'
import { initializeDocumentCore } from '../lib/initializeDocument'
import type { DocumentState } from '../lib/types'
import { documentCache } from '../lib/document-cache'

export interface UseDocumentInitResult {
  yDoc: Y.Doc | null
  isLoading: boolean
  error: Error | null
}

/**
 * Hook to initialize Y.Doc with decrypted content.
 * Requires document metadata and KEK to be already available.
 */
export function useDocumentInit(
  documentId: string,
  document: DocumentResponse | null,
  kek: Uint8Array | null,
  retryTrigger: number,
): UseDocumentInitResult {
  const [yDoc, setYDoc] = useState<Y.Doc | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    let cancelled = false

    function applyDocState(state: DocumentState) {
      setYDoc(state.yDoc)
      setIsLoading(false)
    }

    async function initializeYDoc() {
      if (!document || !kek) {
        return
      }

      // Already cached
      const existingState = documentCache.getValue(documentId)
      if (existingState) {
        if (!cancelled) applyDocState(existingState)
        return
      }

      // Wait for existing initialization
      const existingPromise = documentCache.getPromise(documentId)
      if (existingPromise) {
        const state = await existingPromise
        if (!cancelled && state) applyDocState(state)
        return
      }

      // Start new initialization
      const initPromise = (async (): Promise<DocumentState | null> => {
        try {
          const result = await initializeDocumentCore({
            documentId,
            document,
            kek,
          })
          return result
        } catch (err) {
          if (!cancelled) {
            setError(err instanceof Error ? err : new Error('Failed to initialize document'))
          }
          return null
        } finally {
          documentCache.removePromise(documentId)
        }
      })()

      documentCache.setPromise(documentId, initPromise)

      const state = await initPromise
      if (!cancelled) {
        if (state) applyDocState(state)
        else setIsLoading(false)
      }
    }

    initializeYDoc()

    return () => {
      cancelled = true
    }
  }, [document, kek, documentId, retryTrigger])

  return { yDoc, isLoading, error }
}
