/**
 * Git Import for KeyVault Git Sync
 *
 * Imports a Git repository into the workspace.
 */

import * as Y from 'yjs'

import {
  updateDocumentContent as apiUpdateDocumentContent,
} from '@/shared/api/client'

import { createDocument } from '@/entities/document'

import {
  getKeyVaultService,
  fetchDocumentKeys,
  createDocumentDek,
  encrypt,
  getSodium,
} from '@/features/security'

import { GitClient } from './git-client'
import type { GitCredentials } from './git-credentials'


export interface ImportResult {
  success: boolean
  message: string
  docsCreated: number
  attachmentsFound: number
}

export interface ImportProgress {
  phase: 'cloning' | 'scanning' | 'importing' | 'done'
  current: number
  total: number
  currentFile?: string
}

export type ProgressCallback = (progress: ImportProgress) => void

/**
 * Import a Git repository into the workspace.
 *
 * This function clones the repository and creates documents from markdown files.
 */
export async function importFromGit(
  workspaceId: string,
  repositoryUrl: string,
  credentials: GitCredentials,
  onProgress?: ProgressCallback
): Promise<ImportResult> {
  const service = getKeyVaultService()
  if (!service.isUnlocked) {
    return {
      success: false,
      message: 'KeyVault is locked. Please unlock first.',
      docsCreated: 0,
      attachmentsFound: 0,
    }
  }

  const gitClient = new GitClient(workspaceId)

  // 1. Clone repository
  onProgress?.({
    phase: 'cloning',
    current: 0,
    total: 1,
  })

  try {
    await gitClient.clone(repositoryUrl, credentials)
  } catch (error) {
    return {
      success: false,
      message: `Failed to clone repository: ${error instanceof Error ? error.message : 'Unknown error'}`,
      docsCreated: 0,
      attachmentsFound: 0,
    }
  }

  // 2. Scan files
  onProgress?.({
    phase: 'scanning',
    current: 0,
    total: 1,
  })

  let docsCreated = 0
  let attachmentsFound = 0

  try {
    const allFiles = await listAllFiles(gitClient, '')

    const markdownFiles: string[] = []
    const attachmentFiles: string[] = []

    for (const file of allFiles) {
      if (file.endsWith('.md') || file.endsWith('.markdown')) {
        markdownFiles.push(file)
      } else if (isAttachment(file)) {
        attachmentFiles.push(file)
      }
    }

    attachmentsFound = attachmentFiles.length

    // 3. Import markdown files as documents
    onProgress?.({
      phase: 'importing',
      current: 0,
      total: markdownFiles.length,
    })

    for (let i = 0; i < markdownFiles.length; i++) {
      const filePath = markdownFiles[i]

      onProgress?.({
        phase: 'importing',
        current: i,
        total: markdownFiles.length,
        currentFile: filePath,
      })

      try {
        // Read file content
        const rawContent = await gitClient.readFile(filePath)

        // Strip frontmatter from markdown
        const content = stripFrontmatter(rawContent)

        // Extract title from filename (remove extension and path)
        const fileName = filePath.split('/').pop() || filePath
        const title = fileName.replace(/\.(md|markdown)$/i, '') || 'Untitled'

        // Create document
        const doc = await createDocument({ title, parent_id: null })

        // Create DEK for the document
        await createDocumentDek(doc.id, workspaceId)

        // Get DEK for encryption
        const { dek } = await fetchDocumentKeys(doc.id, workspaceId)

        // Create Yjs doc and set content
        const ydoc = new Y.Doc()
        ydoc.getText('content').insert(0, content)

        // Get Yjs state as bytes
        const yjsState = Y.encodeStateAsUpdateV2(ydoc)
        ydoc.destroy()

        // Encrypt content with DEK
        const { ciphertext, nonce } = await encrypt(dek, yjsState)

        // Convert to base64 for API
        const sodium = await getSodium()
        const contentBase64 = sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL)
        const nonceBase64 = sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL)

        // Update document content with encrypted data
        await apiUpdateDocumentContent({
          id: doc.id,
          requestBody: {
            content: contentBase64,
            nonce: nonceBase64,
          },
        })

        docsCreated++
      } catch (error) {
        console.error(`[git-import] Failed to import ${filePath}:`, error)
        // Continue with other files
      }
    }

    onProgress?.({
      phase: 'done',
      current: docsCreated,
      total: markdownFiles.length,
    })
  } catch (error) {
    return {
      success: false,
      message: `Failed to import repository: ${error instanceof Error ? error.message : 'Unknown error'}`,
      docsCreated,
      attachmentsFound,
    }
  }

  return {
    success: true,
    message: `Repository imported. Created ${docsCreated} documents.`,
    docsCreated,
    attachmentsFound,
  }
}

/**
 * Get list of markdown files from cloned repository
 */
export async function getImportableFiles(workspaceId: string): Promise<{
  markdownFiles: string[]
  attachmentFiles: string[]
}> {
  const gitClient = new GitClient(workspaceId)

  const isInitialized = await gitClient.isInitialized()
  if (!isInitialized) {
    return { markdownFiles: [], attachmentFiles: [] }
  }

  try {
    const allFiles = await listAllFiles(gitClient, '')

    const markdownFiles: string[] = []
    const attachmentFiles: string[] = []

    for (const file of allFiles) {
      if (file.endsWith('.md') || file.endsWith('.markdown')) {
        markdownFiles.push(file)
      } else if (isAttachment(file)) {
        attachmentFiles.push(file)
      }
    }

    return { markdownFiles, attachmentFiles }
  } catch {
    return { markdownFiles: [], attachmentFiles: [] }
  }
}

/**
 * Read file content from the cloned repository
 */
export async function readImportFile(
  workspaceId: string,
  filePath: string
): Promise<string> {
  const gitClient = new GitClient(workspaceId)
  return gitClient.readFile(filePath)
}

/**
 * Read binary file from the cloned repository
 */
export async function readImportBinaryFile(
  workspaceId: string,
  filePath: string
): Promise<Uint8Array> {
  const gitClient = new GitClient(workspaceId)
  const content = await gitClient.readFile(filePath)
  // For binary files, we need to read as raw bytes
  // This is a simplified version - real implementation would need proper binary handling
  return new TextEncoder().encode(content)
}

/**
 * List all files recursively
 */
async function listAllFiles(gitClient: GitClient, dirPath: string): Promise<string[]> {
  const files: string[] = []

  try {
    const entries = await gitClient.listFiles(dirPath)

    for (const entry of entries) {
      if (entry === '.git') continue

      const fullPath = dirPath ? `${dirPath}/${entry}` : entry

      try {
        // Try to list as directory
        const subEntries = await gitClient.listFiles(fullPath)
        if (Array.isArray(subEntries) && subEntries.length > 0) {
          // It's a directory
          const subFiles = await listAllFiles(gitClient, fullPath)
          files.push(...subFiles)
        } else {
          // Empty directory or file
          files.push(fullPath)
        }
      } catch {
        // It's a file
        files.push(fullPath)
      }
    }
  } catch {
    // Return empty on error
  }

  return files
}

/**
 * Strip YAML frontmatter from markdown content.
 * Frontmatter is delimited by --- at the start and end.
 */
function stripFrontmatter(content: string): string {
  // Remove BOM if present
  const trimmed = content.replace(/^\uFEFF/, '')

  // Check if content starts with frontmatter delimiter
  const openMatch = trimmed.match(/^---\r?\n/)
  if (!openMatch) {
    return trimmed
  }

  // Find the closing delimiter
  const afterOpen = trimmed.slice(openMatch[0].length)
  const closeMatch = afterOpen.match(/\n---\r?\n/)
  if (!closeMatch) {
    return trimmed
  }

  // Extract body after frontmatter
  const bodyStart = closeMatch.index! + closeMatch[0].length
  return afterOpen.slice(bodyStart)
}

/**
 * Check if file is an attachment (image, etc.)
 */
function isAttachment(filePath: string): boolean {
  const attachmentExtensions = [
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.mp3', '.mp4', '.wav', '.ogg',
    '.zip', '.tar', '.gz',
  ]

  const ext = filePath.substring(filePath.lastIndexOf('.')).toLowerCase()
  return attachmentExtensions.includes(ext)
}

/**
 * Clear the cloned repository
 */
export async function clearImportedRepository(workspaceId: string): Promise<void> {
  const gitClient = new GitClient(workspaceId)
  await gitClient.clear()
}
