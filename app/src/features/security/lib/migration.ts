/**
 * E2EE Migration Helper
 *
 * Handles the migration of existing data to E2EE by generating
 * workspace KEKs and document DEKs.
 */

import {
  me as fetchMe,
  switchWorkspace,
  listDocuments as apiListDocuments,
  migrate as apiMigrate,
} from '@/shared/api'
import type {
  MigrateRequest,
  MemberEncryptedKekRequest,
  EncryptedDekRequest,
} from '@/shared/api'

import { toBase64 } from './crypto'
import {
  generateDocumentDek,
  createEncryptedDekForApi,
} from './keys/document-dek'
import {
  generateWorkspaceKek,
  encryptKekForRecipient,
  encodeKekForApi,
} from './keys/workspace-kek'

export interface MigrationProgress {
  stage: 'preparing' | 'generating_keys' | 'migrating' | 'complete'
  current: number
  total: number
  message: string
}

export interface MigrationResult {
  documentsEncrypted: number
  filesEncrypted: number
  updatesCleared: number
  status: string
}

/**
 * Perform E2EE migration for an existing user.
 *
 * This function:
 * 1. Gets all user's workspaces
 * 2. For each workspace, generates a KEK
 * 3. Lists all documents and generates DEKs
 * 4. Calls the migration API to encrypt existing data
 *
 * @param userPublicKey - User's ECDH public key (for encrypting KEKs)
 * @param userId - User's ID
 * @param onProgress - Optional progress callback
 * @returns Migration result
 */
export async function performMigration(
  userPublicKey: Uint8Array,
  userId: string,
  onProgress?: (progress: MigrationProgress) => void
): Promise<MigrationResult> {
  const report = (progress: MigrationProgress) => {
    onProgress?.(progress)
  }

  report({
    stage: 'preparing',
    current: 0,
    total: 0,
    message: 'Preparing migration...',
  })

  // Get user info with workspaces
  const userInfo = await fetchMe()
  const workspaces = userInfo.workspaces || []

  if (workspaces.length === 0) {
    // No workspaces to migrate
    return {
      documentsEncrypted: 0,
      filesEncrypted: 0,
      updatesCleared: 0,
      status: 'completed',
    }
  }

  // Track original workspace to restore later
  const originalWorkspaceId = userInfo.active_workspace_id

  // Collect all documents across workspaces
  const allDocuments: { workspaceId: string; documentId: string }[] = []

  report({
    stage: 'preparing',
    current: 0,
    total: workspaces.length,
    message: 'Listing documents...',
  })

  // For each workspace, list documents
  for (let i = 0; i < workspaces.length; i++) {
    const workspace = workspaces[i]

    report({
      stage: 'preparing',
      current: i + 1,
      total: workspaces.length,
      message: `Listing documents in ${workspace.name}...`,
    })

    // Switch to this workspace
    await switchWorkspace({ id: workspace.id })

    // List all documents (including archived)
    const docs = await apiListDocuments({ state: 'all' })

    // Add to collection
    for (const doc of docs.items || []) {
      // Only include actual documents, not folders
      if (doc.type === 'document') {
        allDocuments.push({
          workspaceId: workspace.id,
          documentId: doc.id,
        })
      }
    }
  }

  // Restore original workspace
  if (originalWorkspaceId) {
    await switchWorkspace({ id: originalWorkspaceId })
  }

  const totalItems = workspaces.length + allDocuments.length

  report({
    stage: 'generating_keys',
    current: 0,
    total: totalItems,
    message: 'Generating encryption keys...',
  })

  // Generate KEKs for each workspace
  const workspaceKeks: { [key: string]: string } = {}
  const encryptedWorkspaceKeks: { [key: string]: MemberEncryptedKekRequest[] } = {}
  const workspaceKekRaw: { [key: string]: Uint8Array } = {} // Keep raw KEKs for DEK encryption

  for (let i = 0; i < workspaces.length; i++) {
    const workspace = workspaces[i]

    report({
      stage: 'generating_keys',
      current: i + 1,
      total: totalItems,
      message: `Generating key for workspace "${workspace.name}"...`,
    })

    // Generate KEK
    const kek = await generateWorkspaceKek()
    workspaceKekRaw[workspace.id] = kek

    // Store raw KEK (base64) for server-side encryption
    workspaceKeks[workspace.id] = await toBase64(kek)

    // Encrypt KEK for the current user
    const { encryptedKek, ephemeralPublicKey, nonce } = await encryptKekForRecipient(
      kek,
      userPublicKey
    )
    const encryptedKekBase64 = await encodeKekForApi(encryptedKek, ephemeralPublicKey, nonce)

    encryptedWorkspaceKeks[workspace.id] = [
      {
        userId: userId,
        encryptedKek: encryptedKekBase64,
      },
    ]
  }

  // Generate DEKs for each document
  const documentDeks: { [key: string]: string } = {}
  const encryptedDocumentDeks: { [key: string]: EncryptedDekRequest } = {}

  for (let i = 0; i < allDocuments.length; i++) {
    const { workspaceId, documentId } = allDocuments[i]

    report({
      stage: 'generating_keys',
      current: workspaces.length + i + 1,
      total: totalItems,
      message: `Generating key for document ${i + 1}/${allDocuments.length}...`,
    })

    // Generate DEK
    const dek = await generateDocumentDek()

    // Store raw DEK (base64) for server-side encryption
    documentDeks[documentId] = await toBase64(dek)

    // Encrypt DEK with workspace KEK
    const kek = workspaceKekRaw[workspaceId]
    if (!kek) {
      throw new Error(`No KEK found for workspace ${workspaceId}`)
    }

    const { encryptedDek, nonce } = await createEncryptedDekForApi(dek, kek)
    encryptedDocumentDeks[documentId] = {
      encryptedDek,
      nonce,
    }
  }

  report({
    stage: 'migrating',
    current: 0,
    total: 1,
    message: 'Encrypting data on server...',
  })

  // Call the migration API
  const migrateRequest: MigrateRequest = {
    workspaceKeks,
    documentDeks,
    encryptedWorkspaceKeks,
    encryptedDocumentDeks,
  }

  const result = await apiMigrate({ requestBody: migrateRequest })

  report({
    stage: 'complete',
    current: 1,
    total: 1,
    message: 'Migration complete!',
  })

  // Clear raw KEKs from memory
  for (const kek of Object.values(workspaceKekRaw)) {
    kek.fill(0)
  }

  return {
    documentsEncrypted: result.documentsEncrypted,
    filesEncrypted: result.filesEncrypted,
    updatesCleared: result.updatesCleared,
    status: result.status,
  }
}

/**
 * Check if migration is needed for the current user.
 */
export async function checkNeedsMigration(): Promise<boolean> {
  const userInfo = await fetchMe()
  const workspaces = userInfo.workspaces || []

  // If user has workspaces but hasn't completed E2EE setup, migration is needed
  return workspaces.length > 0
}
