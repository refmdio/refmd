/**
 * Fetch and decrypt document content for search indexing
 *
 * All documents use E2EE (End-to-End Encryption):
 * 1. Fetches encrypted snapshot and pending updates from API
 * 2. Decrypts using document DEK (Data Encryption Key)
 * 3. Reconstructs Yjs document and extracts plain text
 */

import * as Y from 'yjs'

import {
  getDocumentContent,
  getDocumentKey,
  getMyWorkspaceKey,
  type EncryptedUpdateEntry,
} from '@/shared/api/client'

import {
  decrypt,
  getKeyManager,
  decryptDekFromApiResponse,
  getSodium,
} from '@/features/e2ee'

/**
 * Fetch document content and return plain text.
 *
 * All documents are E2EE encrypted. This function:
 * 1. Fetches encrypted snapshot and updates from API
 * 2. Decrypts using document DEK (Data Encryption Key)
 * 3. Reconstructs Yjs document and extracts text
 *
 * @param documentId - Document ID
 * @param workspaceId - Workspace ID (for KEK lookup)
 * @returns Plain text content or empty string on failure
 */
export async function fetchDecryptedContent(
  documentId: string,
  workspaceId: string
): Promise<string> {
  try {
    // 1. Fetch content from API
    const contentRes = await getDocumentContent({ id: documentId })

    // Check if we have any content to work with
    const hasSnapshot = contentRes.content && contentRes.content.length > 0
    const hasUpdates = contentRes.updates && contentRes.updates.length > 0

    if (!hasSnapshot && !hasUpdates) {
      return ''
    }

    const sodium = await getSodium()
    const doc = new Y.Doc()

    // 2. All documents are E2EE - get decryption keys
    const keyManager = getKeyManager()
    if (!keyManager.isUnlocked) {
      doc.destroy()
      return ''
    }

    // Get workspace KEK
    const kek = await keyManager.getWorkspaceKek(workspaceId, async () => {
      const response = await getMyWorkspaceKey({ id: workspaceId })
      return response.encryptedKek
    })

    // Get document DEK
    const keyRes = await getDocumentKey({ id: documentId })
    const dek = await decryptDekFromApiResponse(keyRes.encryptedDek, keyRes.nonce, kek)

    // 3. Apply snapshot if present
    if (hasSnapshot) {
      const encryptedContent = sodium.from_base64(contentRes.content, sodium.base64_variants.ORIGINAL)
      const nonce = sodium.from_base64(contentRes.nonce!, sodium.base64_variants.ORIGINAL)
      const yjsState = await decrypt(dek, encryptedContent, nonce)
      Y.applyUpdateV2(doc, yjsState)
    }

    // 4. Apply pending updates
    if (hasUpdates) {
      for (const update of contentRes.updates as EncryptedUpdateEntry[]) {
        const encryptedData = sodium.from_base64(update.data, sodium.base64_variants.ORIGINAL)
        const nonce = sodium.from_base64(update.nonce!, sodium.base64_variants.ORIGINAL)
        const yjsUpdate = await decrypt(dek, encryptedData, nonce)
        Y.applyUpdateV2(doc, yjsUpdate)
      }
    }

    const text = doc.getText('content').toString()
    doc.destroy()

    return text
  } catch {
    return ''
  }
}
