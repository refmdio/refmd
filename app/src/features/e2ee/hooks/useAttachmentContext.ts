/**
 * Hook to set up decryption context for attachments
 *
 * This hook registers the decryption context (workspaceId, token) for a document
 * so that the attachment Web Component can decrypt files.
 */

import { useLayoutEffect, useEffect } from 'react'

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
 * Context and file map initialization are started synchronously during render
 * to ensure they're available before child components' useLayoutEffect runs.
 */
export function useAttachmentContext(options: UseAttachmentContextOptions): void {
  const { documentId, workspaceId, token, setAsDefault } = options

  // Set context and start file map init synchronously during render
  // (before children's useLayoutEffect)
  if (workspaceId) {
    const context = { workspaceId, token }
    if (setAsDefault) {
      setDefaultDecryptionContext(context)
    } else if (documentId) {
      setDecryptionContext(documentId, context)
    }

    // Start file map initialization for specific document
    if (documentId) {
      // Start immediately (async but started sync)
      // This ensures waitForFileMap can return the pending promise
      initFileMap(documentId, workspaceId).catch(() => {
        // Errors handled by waitForFileMap callers
      })
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

  // Cleanup file map on unmount
  useEffect(() => {
    return () => {
      if (documentId) {
        clearFileMap(documentId)
      }
    }
  }, [documentId, workspaceId])
}
