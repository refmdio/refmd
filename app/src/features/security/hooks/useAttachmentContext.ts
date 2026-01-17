/**
 * Hook to set up decryption context for attachments
 *
 * This hook registers the decryption context (DEK, token) for a document
 * so that the attachment Web Component can decrypt files.
 */

import { useLayoutEffect, useEffect, useRef } from 'react'

import {
  setDecryptionContext,
  clearDecryptionContext,
  setDefaultDecryptionContext,
  initFileMap,
  clearFileMap,
} from '@/entities/file'

import { fetchDocumentKeys } from '@/features/security'

export interface UseAttachmentContextOptions {
  /** Document ID */
  documentId?: string
  /** Workspace ID for key access */
  workspaceId?: string | null
  /** Share token for authentication */
  token?: string
  /** Whether to set as default context (for all documents) */
  setAsDefault?: boolean
}

/**
 * Set up decryption context for attachments
 *
 * When a documentId and workspaceId are provided, this hook fetches the DEK
 * and registers the context so that attachments can be decrypted when downloaded
 * or previewed.
 */
export function useAttachmentContext(options: UseAttachmentContextOptions): void {
  const { documentId, workspaceId, token, setAsDefault } = options
  const initStartedRef = useRef(false)

  // Initialize context and file map
  useEffect(() => {
    if (!workspaceId || !documentId) return

    let cancelled = false
    initStartedRef.current = true

    ;(async () => {
      try {
        // Fetch DEK for this document
        const { dek } = await fetchDocumentKeys(documentId, workspaceId)
        if (cancelled) return

        // Set context with DEK
        const context = { dek, token }
        if (setAsDefault) {
          setDefaultDecryptionContext(context)
        } else {
          setDecryptionContext(documentId, context)
        }

        // Initialize file map with DEK
        initFileMap(documentId, dek).catch(() => {
          // Errors handled by waitForFileMap callers
        })
      } catch (err) {
        console.warn('[useAttachmentContext] Failed to fetch DEK:', err)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [documentId, workspaceId, token, setAsDefault])

  // Cleanup on unmount or when dependencies change
  useLayoutEffect(() => {
    if (!workspaceId) return

    return () => {
      if (setAsDefault) {
        setDefaultDecryptionContext(null)
      } else if (documentId) {
        clearDecryptionContext(documentId)
      }
    }
  }, [documentId, workspaceId, token, setAsDefault])

  // Cleanup file map on unmount
  useEffect(() => {
    return () => {
      if (documentId) {
        clearFileMap(documentId)
      }
    }
  }, [documentId, workspaceId])
}
