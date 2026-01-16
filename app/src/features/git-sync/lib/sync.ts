/**
 * Git Sync Logic for E2EE
 *
 * Handles synchronization between encrypted documents and Git repository.
 * All Git operations are performed client-side using isomorphic-git.
 * Network operations go through backend proxy (HTTPS) or tunnel (SSH).
 */

import * as Y from 'yjs'

import {
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
  decryptString,
} from '@/features/security'

import { GitClient } from './git-client'
import { loadGitCredentials, type GitCredentials } from './git-credentials'
import { calculateDirtyFiles } from './dirty-calculator'

export interface SyncOptions {
  message?: string
  workspaceId: string
}

export interface SyncResult {
  success: boolean
  message: string
  filesChanged: number
  commitSha?: string
}

/**
 * Decrypt document title from API response
 */
export async function decryptDocumentTitle(
  doc: Document,
  workspaceId: string
): Promise<string> {
  if (!doc.encryptedTitle || !doc.encryptedTitleNonce) {
    return doc.title || 'Untitled'
  }

  try {
    const keyManager = getKeyManager()
    const kek = await keyManager.getWorkspaceKek(workspaceId, async () => {
      const response = await getMyWorkspaceKey({ id: workspaceId })
      return response.encryptedKek
    })

    const keyRes = await getDocumentKey({ id: doc.id })
    const dek = await decryptDekFromApiResponse(keyRes.encryptedDek, keyRes.nonce, kek)

    const sodium = await getSodium()
    const ciphertext = sodium.from_base64(doc.encryptedTitle, sodium.base64_variants.ORIGINAL)
    const nonce = sodium.from_base64(doc.encryptedTitleNonce, sodium.base64_variants.ORIGINAL)
    return await decryptString(dek, ciphertext, nonce)
  } catch {
    return doc.title || 'Untitled'
  }
}

/**
 * Fetch and decrypt document content
 */
export async function fetchDecryptedDocumentContent(
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
 * Sync workspace documents to Git repository
 */
export async function syncWorkspaceToGit(options: SyncOptions): Promise<SyncResult> {
  const { workspaceId, message } = options

  // 1. Check E2EE unlock status
  const keyManager = getKeyManager()
  if (!keyManager.isUnlocked) {
    return {
      success: false,
      message: 'E2EE is locked. Please unlock first.',
      filesChanged: 0,
    }
  }

  // 2. Load Git credentials
  const credentials = await loadGitCredentials(workspaceId)
  if (!credentials) {
    return {
      success: false,
      message: 'Git credentials not configured.',
      filesChanged: 0,
    }
  }

  // 3. Initialize Git client
  const git = new GitClient(workspaceId)

  // 4. Check if repository is initialized
  const isInitialized = await git.isInitialized()
  if (!isInitialized) {
    // Clone the repository first
    try {
      await git.clone(credentials.repositoryUrl, credentials)
    } catch (error) {
      return {
        success: false,
        message: `Failed to clone repository: ${error instanceof Error ? error.message : 'Unknown error'}`,
        filesChanged: 0,
      }
    }
  }

  // 5. Pull latest changes
  try {
    await git.pull(credentials)
  } catch (error) {
    // Pull might fail if there are conflicts - we'll handle that later
    console.warn('Pull failed, continuing with sync:', error)
  }

  // 6. Calculate dirty files (on-demand comparison with Git HEAD)
  const dirtyFiles = await calculateDirtyFiles(workspaceId, git)

  if (dirtyFiles.length === 0) {
    return {
      success: true,
      message: 'No changes to commit.',
      filesChanged: 0,
    }
  }

  // 7. Process each dirty file
  let filesChanged = 0
  for (const dirty of dirtyFiles) {
    try {
      if (dirty.status === 'deleted') {
        // Remove file from Git
        await git.remove(dirty.path)
      } else {
        // Added or modified - fetch and write content
        const content = await fetchDecryptedDocumentContent(dirty.documentId, workspaceId)
        await git.writeFile(dirty.path, content)
        await git.add(dirty.path)
      }
      filesChanged++
    } catch (error) {
      console.error(`Failed to sync file ${dirty.path}:`, error)
    }
  }

  // 8. Check if there are staged changes to commit
  const status = await git.status()
  const hasChanges = status.some(([, head, workdir, stage]) => {
    // Check for any changes (modified, added, deleted)
    return head !== workdir || head !== stage || workdir !== stage
  })

  if (!hasChanges) {
    return {
      success: true,
      message: 'No changes to commit.',
      filesChanged: 0,
    }
  }

  // 9. Create commit
  const commitMessage = message || `Sync from RefMD at ${new Date().toISOString()}`
  let commitSha: string
  try {
    commitSha = await git.commit(commitMessage)
  } catch (error) {
    return {
      success: false,
      message: `Failed to commit: ${error instanceof Error ? error.message : 'Unknown error'}`,
      filesChanged,
    }
  }

  // 10. Push to remote
  try {
    await git.push(credentials)
  } catch (error) {
    return {
      success: false,
      message: `Committed locally but failed to push: ${error instanceof Error ? error.message : 'Unknown error'}`,
      filesChanged,
      commitSha,
    }
  }

  return {
    success: true,
    message: 'Sync completed successfully.',
    filesChanged,
    commitSha,
  }
}

/**
 * Initialize Git repository for workspace
 */
export async function initGitRepository(
  workspaceId: string,
  repositoryUrl: string,
  credentials: GitCredentials
): Promise<{ success: boolean; message: string }> {
  const keyManager = getKeyManager()
  if (!keyManager.isUnlocked) {
    return {
      success: false,
      message: 'E2EE is locked. Please unlock first.',
    }
  }

  const git = new GitClient(workspaceId)

  try {
    await git.clone(repositoryUrl, credentials)
    return {
      success: true,
      message: 'Repository initialized successfully.',
    }
  } catch (error) {
    return {
      success: false,
      message: `Failed to clone repository: ${error instanceof Error ? error.message : 'Unknown error'}`,
    }
  }
}

/**
 * Get Git status for workspace
 */
export async function getGitStatus(workspaceId: string): Promise<{
  initialized: boolean
  branch?: string
  changes: number
  ahead: number
  behind: number
}> {
  const git = new GitClient(workspaceId)

  const isInitialized = await git.isInitialized()
  if (!isInitialized) {
    return {
      initialized: false,
      changes: 0,
      ahead: 0,
      behind: 0,
    }
  }

  const branch = await git.currentBranch()
  const status = await git.status()

  // Count changed files
  const changes = status.filter(([, head, workdir, stage]) => {
    return head !== workdir || head !== stage || workdir !== stage
  }).length

  return {
    initialized: true,
    branch: branch || undefined,
    changes,
    ahead: 0, // TODO: Calculate ahead/behind with fetch
    behind: 0,
  }
}

/**
 * Get Git commit history for workspace
 */
export async function getGitHistory(
  workspaceId: string,
  depth: number = 20
): Promise<Array<{
  sha: string
  message: string
  author: string
  date: Date
}>> {
  const git = new GitClient(workspaceId)

  const isInitialized = await git.isInitialized()
  if (!isInitialized) {
    return []
  }

  try {
    const logs = await git.log(depth)
    return logs.map((entry) => ({
      sha: entry.oid,
      message: entry.commit.message,
      author: entry.commit.author.name,
      date: new Date(entry.commit.author.timestamp * 1000),
    }))
  } catch {
    return []
  }
}
