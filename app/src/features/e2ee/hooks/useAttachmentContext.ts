/**
 * Hook to set up decryption context for attachments
 *
 * This hook registers the decryption context (workspaceId, token) for a document
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
 * When a documentId and workspaceId are provided, this hook registers
 * the context so that attachments can be decrypted when downloaded
 * or previewed.
 *
 * Context is set synchronously during render to ensure it's available
 * before child components' useLayoutEffect runs.
 */
export function useAttachmentContext(options: UseAttachmentContextOptions): void {
  const { documentId, workspaceId, token, setAsDefault } = options
  const mountedRef = useRef(true)

  // Set context synchronously during render (before children's useLayoutEffect)
  if (workspaceId) {
    const context = { workspaceId, token }
    if (setAsDefault) {
      setDefaultDecryptionContext(context)
    } else if (documentId) {
      setDecryptionContext(documentId, context)
    }
  }

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

  // Initialize file map asynchronously
  useEffect(() => {
    mountedRef.current = true

    if (!documentId || !workspaceId) return

    // Initialize file map for this document
    initFileMap(documentId, workspaceId).catch((error) => {
      // Only log if still mounted (avoid logging for cancelled requests)
      if (mountedRef.current) {
        console.warn('[useAttachmentContext] Failed to initialize file map:', error)
      }
    })

    return () => {
      mountedRef.current = false
      // Clear file map on cleanup
      if (documentId) {
        clearFileMap(documentId)
      }
    }
  }, [documentId, workspaceId])
}
