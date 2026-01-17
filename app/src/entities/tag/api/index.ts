/**
 * Tag API with E2EE support
 *
 * All tags are deterministically encrypted using HMAC-SHA256.
 * This allows server-side grouping while keeping tag names private.
 */

import {
  listTags as apiListTags,
  getDocumentTags as apiGetDocumentTags,
  updateDocumentTags as apiUpdateDocumentTags,
} from '@/shared/api'
import { extractTags, getTagLookupManager } from '@/shared/lib/tags'

// Query keys for React Query
export const tagKeys = {
  all: ['tags'] as const,
  list: (workspaceId: string) => ['tags', { workspaceId }] as const,
  document: (documentId: string) => ['tags', 'document', documentId] as const,
}

// Types
export interface DecryptedTag {
  name: string
  documentCount: number
}

export interface DecryptedDocumentTag {
  id: string
  name: string
  createdAt: string
}

/**
 * List all tags for a workspace (decrypted).
 *
 * @param kek - Workspace KEK for decryption
 * @returns Array of decrypted tags with document counts
 */
export async function listDecryptedTags(kek: Uint8Array): Promise<DecryptedTag[]> {
  const response = await apiListTags({})

  if (!response.tags || response.tags.length === 0) {
    return []
  }

  // Setup lookup manager with provided KEK
  const lookupManager = getTagLookupManager()
  lookupManager.setKek(kek)

  // Try to decrypt each tag
  const results: DecryptedTag[] = []
  for (const tag of response.tags) {
    const decrypted = await lookupManager.decrypt(tag.encryptedName)
    results.push({
      name: decrypted ?? tag.encryptedName, // Fallback to encrypted if unknown
      documentCount: tag.documentCount,
    })
  }

  return results
}

/**
 * Get tags for a specific document (decrypted).
 *
 * @param documentId - Document ID
 * @param kek - Workspace KEK for decryption
 * @returns Array of decrypted document tags
 */
export async function getDecryptedDocumentTags(
  documentId: string,
  kek: Uint8Array
): Promise<DecryptedDocumentTag[]> {
  const response = await apiGetDocumentTags({ id: documentId })

  if (!response.tags || response.tags.length === 0) {
    return []
  }

  // Setup lookup manager with provided KEK
  const lookupManager = getTagLookupManager()
  lookupManager.setKek(kek)

  // Try to decrypt each tag
  const results: DecryptedDocumentTag[] = []
  for (const tag of response.tags) {
    const decrypted = await lookupManager.decrypt(tag.encryptedName)
    results.push({
      id: tag.id,
      name: decrypted ?? tag.encryptedName,
      createdAt: tag.createdAt,
    })
  }

  return results
}

/**
 * Update document tags with encryption.
 *
 * @param documentId - Document ID
 * @param kek - Workspace KEK for encryption
 * @param tags - Array of plaintext tag names
 */
export async function updateEncryptedDocumentTags(
  documentId: string,
  kek: Uint8Array,
  tags: string[]
): Promise<void> {
  if (tags.length === 0) {
    // Clear all tags
    await apiUpdateDocumentTags({
      id: documentId,
      requestBody: { encryptedTags: [] },
    })
    return
  }

  // Setup lookup manager with provided KEK
  const lookupManager = getTagLookupManager()
  lookupManager.setKek(kek)

  // Encrypt each tag and add to known tags
  const encryptedTags = await Promise.all(
    tags.map(async (tag) => {
      const encrypted = await lookupManager.encrypt(tag)
      return { encryptedName: encrypted }
    })
  )

  await apiUpdateDocumentTags({
    id: documentId,
    requestBody: { encryptedTags },
  })
}

/**
 * Extract tags from markdown content and update document tags.
 *
 * This is the main function to call when a document is saved.
 * It extracts #tags from the markdown and sends encrypted tags to the server.
 *
 * @param documentId - Document ID
 * @param kek - Workspace KEK for encryption
 * @param markdownContent - Raw markdown content
 * @returns Array of extracted tag names
 */
export async function updateDocumentTagsFromContent(
  documentId: string,
  kek: Uint8Array,
  markdownContent: string
): Promise<string[]> {
  // Extract tags from markdown
  const tags = extractTags(markdownContent)

  // Update with encrypted tags
  await updateEncryptedDocumentTags(documentId, kek, tags)

  return tags
}

/**
 * Add known tags to the lookup manager for decryption.
 *
 * Call this when you know the plaintext of some tags
 * (e.g., from document content extraction).
 *
 * @param tags - Array of plaintext tag names
 */
export function addKnownTags(tags: string[]): void {
  const lookupManager = getTagLookupManager()
  lookupManager.addKnownTags(tags)
}

/**
 * Encrypt a plaintext tag for API calls.
 *
 * @param tag - Plaintext tag name
 * @param kek - Workspace KEK for encryption
 * @returns Base64-encoded encrypted tag
 */
export async function encryptTagForApi(
  tag: string,
  kek: Uint8Array
): Promise<string> {
  const lookupManager = getTagLookupManager()
  lookupManager.setKek(kek)
  return lookupManager.encrypt(tag)
}

/**
 * Legacy function for backward compatibility.
 * Simply calls the API without decryption.
 *
 * @deprecated Use listDecryptedTags instead
 */
export async function listTags(q?: string) {
  return apiListTags({ q: q as string | undefined })
}
