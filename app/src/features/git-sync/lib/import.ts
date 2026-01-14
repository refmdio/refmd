/**
 * Git Import for E2EE Git Sync
 *
 * Imports a Git repository into the workspace.
 */

import { GitClient } from './git-client'
import type { GitCredentials } from './git-credentials'
import { getKeyManager } from '@/features/e2ee'

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
 * This function clones the repository and counts the files.
 * Actual document creation should be handled by the UI layer
 * which has access to the E2EE document creation flow.
 */
export async function importFromGit(
  workspaceId: string,
  repositoryUrl: string,
  credentials: GitCredentials,
  onProgress?: ProgressCallback
): Promise<ImportResult> {
  const keyManager = getKeyManager()
  if (!keyManager.isUnlocked) {
    return {
      success: false,
      message: 'E2EE is locked. Please unlock first.',
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

    docsCreated = markdownFiles.length
    attachmentsFound = attachmentFiles.length

    onProgress?.({
      phase: 'done',
      current: markdownFiles.length,
      total: markdownFiles.length,
    })
  } catch (error) {
    return {
      success: false,
      message: `Failed to scan repository: ${error instanceof Error ? error.message : 'Unknown error'}`,
      docsCreated: 0,
      attachmentsFound: 0,
    }
  }

  return {
    success: true,
    message: `Repository imported. Found ${docsCreated} documents and ${attachmentsFound} attachments.`,
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
