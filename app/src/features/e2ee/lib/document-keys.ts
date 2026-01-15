/**
 * E2EE Document Key Management
 *
 * Helpers for creating documents with E2EE encryption keys.
 */

import {
  getKeyManager,
  generateDocumentDek,
  createEncryptedDekForApi,
} from './keys'
import {
  storeDocumentKey,
  getMyWorkspaceKey,
  getDocumentKey,
} from '@/shared/api'

/**
 * Generate and store a DEK for a newly created document.
 *
 * This should be called immediately after creating a document.
 *
 * @param documentId - The ID of the newly created document
 * @param workspaceId - The workspace ID (for fetching KEK)
 * @throws Error if E2EE is not unlocked or key operations fail
 */
export async function createDocumentDek(
  documentId: string,
  workspaceId: string
): Promise<void> {
  const km = getKeyManager()

  // Ensure E2EE is unlocked
  if (!km.isUnlocked) {
    throw new Error('E2EE session is locked. Please unlock first.')
  }

  // Get workspace KEK
  const kek = await km.getWorkspaceKek(workspaceId, async () => {
    const response = await getMyWorkspaceKey({ id: workspaceId })
    return response.encryptedKek
  })

  // Generate DEK for the new document
  const dek = await generateDocumentDek()

  // Encrypt DEK with workspace KEK
  const { encryptedDek, nonce } = await createEncryptedDekForApi(dek, kek)

  // Store the encrypted DEK
  await storeDocumentKey({
    id: documentId,
    requestBody: {
      encryptedDek,
      nonce,
      keyVersion: 1, // Initial version for new document
    },
  })

  // Clear DEK from memory
  dek.fill(0)
}

/**
 * Check if E2EE is enabled and unlocked.
 */
export function isE2EEReady(): boolean {
  const km = getKeyManager()
  return km.isInitialized && km.isUnlocked
}

/**
 * Create DEK for a new document if E2EE is enabled.
 *
 * This is a safe wrapper that does nothing if E2EE is not set up or unlocked.
 * Use this in document creation flows.
 *
 * @param documentId - The ID of the newly created document
 * @param workspaceId - The workspace ID (for fetching KEK)
 * @returns true if DEK was created, false if E2EE is not enabled
 */
export async function createDocumentDekIfNeeded(
  documentId: string,
  workspaceId: string | null
): Promise<boolean> {
  if (!workspaceId) {
    console.warn('[e2ee] Cannot create DEK: no workspace ID')
    return false
  }

  if (!isE2EEReady()) {
    // E2EE not enabled or not unlocked, skip DEK creation
    return false
  }

  try {
    await createDocumentDek(documentId, workspaceId)
    return true
  } catch (err) {
    console.error('[e2ee] Failed to create document DEK:', err)
    throw err
  }
}

/**
 * Get the DEK for a document (for plugin use).
 *
 * This is a convenience function for effect handlers that need to
 * encrypt data for a newly created document.
 *
 * @param documentId - The document ID
 * @param workspaceId - The workspace ID (for fetching KEK)
 * @returns The DEK as Uint8Array, or null if E2EE is not enabled
 */
export async function getDocumentDekForPlugin(
  documentId: string,
  workspaceId: string
): Promise<Uint8Array | null> {
  if (!isE2EEReady()) {
    return null
  }

  const km = getKeyManager()

  try {
    // Get workspace KEK
    const kek = await km.getWorkspaceKek(workspaceId, async () => {
      const response = await getMyWorkspaceKey({ id: workspaceId })
      return response.encryptedKek
    })

    // Get and decrypt document DEK
    const dek = await km.getDocumentDek(documentId, kek, async () => {
      const response = await getDocumentKey({ id: documentId })
      return { encryptedDek: response.encryptedDek, nonce: response.nonce }
    })

    return dek
  } catch (err) {
    console.error('[e2ee] Failed to get document DEK:', err)
    return null
  }
}
