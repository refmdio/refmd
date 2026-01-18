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
import { validateShareToken } from '@/entities/share'

import { useShareContextOptional } from '@/features/sharing'

import { getSodium } from '../lib/crypto'
import { fetchDocumentKeys } from '../lib/key-helpers'
import { extractShareKeyFromFragment, decryptDekWithShareKey } from '../lib/keys'

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

  // Try to get share context (available when navigating from folder share page)
  const shareCtx = useShareContextOptional()

  // Initialize context and file map
  useEffect(() => {
    if (!documentId) return

    let cancelled = false
    initStartedRef.current = true

    ;(async () => {
      try {
        let dek: Uint8Array | null = null

        if (token) {
          // Shared documents: try ShareContext first, then fall back to URL fragment
          let shareKey = shareCtx?.shareKey ?? null
          let encryptedDekBase64: string | null = null

          // Try to get encrypted DEK from ShareContext (folder share navigation)
          if (shareCtx?.encryptedDeks && documentId) {
            encryptedDekBase64 = shareCtx.encryptedDeks.get(documentId) ?? null
          }

          // Fallback: extract share key from URL fragment (direct document share links)
          if (!shareKey) {
            const fragment = typeof window !== 'undefined' ? window.location.hash : ''
            shareKey = fragment ? await extractShareKeyFromFragment(fragment) : null
          }

          // Fallback: fetch encrypted DEK from API if not in context
          if (!encryptedDekBase64 && shareKey) {
            const shareInfo = await validateShareToken(token)
            encryptedDekBase64 = shareInfo?.encryptedDek ?? null
          }

          if (shareKey && encryptedDekBase64) {
            // Decrypt DEK using share key
            // The encrypted_dek from API has nonce prepended (24 bytes for XChaCha20)
            const sodium = await getSodium()
            const combined = sodium.from_base64(encryptedDekBase64, sodium.base64_variants.ORIGINAL)
            const NONCE_LENGTH = 24
            if (combined.length > NONCE_LENGTH) {
              const nonce = combined.slice(0, NONCE_LENGTH)
              const ciphertext = combined.slice(NONCE_LENGTH)
              const nonceBase64 = sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL)
              const ciphertextBase64 = sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL)
              dek = await decryptDekWithShareKey(ciphertextBase64, nonceBase64, shareKey)
            }
          }
        } else if (workspaceId) {
          // Regular documents: fetch DEK via workspace KEK hierarchy
          const result = await fetchDocumentKeys(documentId, workspaceId)
          dek = result.dek
        }

        if (cancelled) return

        if (!dek) {
          console.warn('[useAttachmentContext] No DEK available')
          return
        }

        // Set context with DEK
        const context = { dek, token }
        if (setAsDefault) {
          setDefaultDecryptionContext(context)
        } else {
          setDecryptionContext(documentId, context)
        }

        // Initialize file map with DEK (pass token for share access)
        initFileMap(documentId, dek, token).catch(() => {
          // Errors handled by waitForFileMap callers
        })
      } catch (err) {
        console.warn('[useAttachmentContext] Failed to fetch DEK:', err)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [documentId, workspaceId, token, setAsDefault, shareCtx])

  // Cleanup on unmount or when dependencies change
  useLayoutEffect(() => {
    // Skip cleanup setup if neither workspaceId nor token is present
    if (!workspaceId && !token) return

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
