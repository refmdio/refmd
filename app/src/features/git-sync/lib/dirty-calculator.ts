/**
 * Dirty File Calculator for E2EE Git Sync
 *
 * Calculates dirty files on-demand by comparing document content with Git HEAD.
 * No persistence - ensures cross-device consistency.
 */

import {
  listDocuments,
  getDocumentContent,
  getDocumentKey,
  getMyWorkspaceKey,
  type Document,
  type EncryptedUpdateEntry,
} from '@/shared/api/client'

import {
  getKeyManager,
  decrypt,
  getSodium,
  decryptDekFromApiResponse,
} from '@/features/e2ee'

import * as Y from 'yjs'

import { GitClient } from './git-client'

export interface DirtyFile {
  path: string
  documentId: string
  status: 'modified' | 'added' | 'deleted'
}

/**
 * Build file path from document
 */
function buildFilePath(doc: Document): string {
  const basePath = doc.desired_path || doc.slug || doc.id

  if (doc.type === 'document' && !basePath.endsWith('.md')) {
    return `${basePath}.md`
  }

  return basePath
}

/**
 * Fetch and decrypt document content
 */
async function fetchDecryptedDocumentContent(
  documentId: string,
  workspaceId: string
): Promise<string> {
  try {
    const contentRes = await getDocumentContent({ id: documentId })

    const hasSnapshot = contentRes.content && contentRes.content.length > 0
    const hasUpdates = contentRes.updates && contentRes.updates.length > 0

    if (!hasSnapshot && !hasUpdates) {
      return ''
    }

    const sodium = await getSodium()
    const doc = new Y.Doc()

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

    // Apply snapshot if present
    if (hasSnapshot) {
      const encryptedContent = sodium.from_base64(contentRes.content, sodium.base64_variants.ORIGINAL)
      const nonce = sodium.from_base64(contentRes.nonce!, sodium.base64_variants.ORIGINAL)
      const yjsState = await decrypt(dek, encryptedContent, nonce)
      Y.applyUpdateV2(doc, yjsState)
    }

    // Apply pending updates
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

/**
 * Calculate dirty files by comparing document content with Git HEAD.
 * This is an on-demand calculation that ensures cross-device consistency.
 */
export async function calculateDirtyFiles(
  workspaceId: string,
  git: GitClient
): Promise<DirtyFile[]> {
  const dirty: DirtyFile[] = []

  // 1. Get all documents in workspace
  const documentsResponse = await listDocuments({ state: 'active' })
  const workspaceDocs = documentsResponse.items.filter(
    (doc) => doc.workspace_id === workspaceId && doc.type === 'document'
  )

  // 2. Get Git status matrix to find all tracked files
  const statusMatrix = await git.status()
  const gitFiles = new Set(statusMatrix.map(([filepath]) => filepath))

  // 3. Check each document against Git
  for (const doc of workspaceDocs) {
    const path = buildFilePath(doc)

    try {
      const gitContent = await git.readFile(path)
      const docContent = await fetchDecryptedDocumentContent(doc.id, workspaceId)

      if (gitContent !== docContent) {
        dirty.push({ path, documentId: doc.id, status: 'modified' })
      }

      // Remove from git files set (we've processed this one)
      gitFiles.delete(path)
    } catch {
      // File doesn't exist in Git = new file
      dirty.push({ path, documentId: doc.id, status: 'added' })
    }
  }

  // 4. Files in Git but not in documents = deleted
  for (const path of gitFiles) {
    if (!path.endsWith('.md')) continue
    // Skip .git directory files
    if (path.startsWith('.git/')) continue

    dirty.push({ path, documentId: '', status: 'deleted' })
  }

  return dirty
}
