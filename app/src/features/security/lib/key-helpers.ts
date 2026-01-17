/**
 * Key Helpers - Simplified API for fetching encryption keys
 *
 * These helper functions eliminate boilerplate code for common key operations.
 * Instead of manually calling getWorkspaceKek with inline fetch functions,
 * just call fetchWorkspaceKek(workspaceId).
 *
 * Before:
 * ```typescript
 * const service = getKeyVaultService()
 * await service.ready()
 * service.ensureUnlocked()
 * const kek = await service.getWorkspaceKek(workspaceId, async () => {
 *   const response = await getMyWorkspaceKey({ id: workspaceId })
 *   return response.encryptedKek
 * })
 * const dek = await service.getDocumentDek(documentId, kek, async () => {
 *   const response = await getDocumentKey({ id: documentId })
 *   return { encryptedDek: response.encryptedDek, nonce: response.nonce }
 * })
 * ```
 *
 * After:
 * ```typescript
 * const { kek, dek } = await fetchDocumentKeys(documentId, workspaceId)
 * ```
 */

import { getMyWorkspaceKey, getDocumentKey } from '@/shared/api/client'

import { getKeyVaultService } from './key-vault-service'

/**
 * Fetch workspace KEK (Key Encryption Key).
 *
 * Auto-initializes KeyVaultService and ensures unlocked state.
 *
 * @param workspaceId - Workspace ID
 * @returns KEK as Uint8Array
 * @throws SessionLockedError if session is locked
 */
export async function fetchWorkspaceKek(workspaceId: string): Promise<Uint8Array> {
  const service = getKeyVaultService()
  return service.getWorkspaceKek(workspaceId, async () => {
    const response = await getMyWorkspaceKey({ id: workspaceId })
    return response.encryptedKek
  })
}

/**
 * Fetch document DEK (Document Encryption Key).
 *
 * Automatically fetches the workspace KEK first if not provided.
 * Auto-initializes KeyVaultService and ensures unlocked state.
 *
 * @param documentId - Document ID
 * @param workspaceId - Workspace ID
 * @returns DEK as Uint8Array
 * @throws SessionLockedError if session is locked
 */
export async function fetchDocumentDek(
  documentId: string,
  workspaceId: string
): Promise<Uint8Array> {
  const kek = await fetchWorkspaceKek(workspaceId)
  const service = getKeyVaultService()
  return service.getDocumentDek(documentId, kek, async () => {
    const response = await getDocumentKey({ id: documentId })
    return { encryptedDek: response.encryptedDek, nonce: response.nonce }
  })
}

/**
 * Fetch both KEK and DEK for a document.
 *
 * Use this when you need both keys (e.g., for encryption operations).
 * Auto-initializes KeyVaultService and ensures unlocked state.
 *
 * @param documentId - Document ID
 * @param workspaceId - Workspace ID
 * @returns Object with kek and dek as Uint8Array
 * @throws SessionLockedError if session is locked
 */
export async function fetchDocumentKeys(
  documentId: string,
  workspaceId: string
): Promise<{ kek: Uint8Array; dek: Uint8Array }> {
  const kek = await fetchWorkspaceKek(workspaceId)
  const service = getKeyVaultService()
  const dek = await service.getDocumentDek(documentId, kek, async () => {
    const response = await getDocumentKey({ id: documentId })
    return { encryptedDek: response.encryptedDek, nonce: response.nonce }
  })
  return { kek, dek }
}
