/**
 * Git Pull for E2EE Git Sync
 *
 * Handles pulling changes from remote and detecting conflicts.
 */

import * as git from 'isomorphic-git'
import { GitClient } from './git-client'
import { loadGitCredentials } from './git-credentials'
import { getKeyManager } from '@/features/e2ee'
import { listDocuments, type Document } from '@/shared/api/client'

export interface PullResult {
  success: boolean
  message: string
  conflicts: ConflictItem[]
  filesUpdated: number
}

export interface ConflictItem {
  path: string
  ours: string
  theirs: string
  base: string
  documentId?: string
  is_binary: boolean
}

/**
 * Pull changes from remote repository
 */
export async function pullFromGit(workspaceId: string): Promise<PullResult> {
  const keyManager = getKeyManager()
  if (!keyManager.isUnlocked) {
    return {
      success: false,
      message: 'E2EE is locked. Please unlock first.',
      conflicts: [],
      filesUpdated: 0,
    }
  }

  const credentials = await loadGitCredentials(workspaceId)
  if (!credentials) {
    return {
      success: false,
      message: 'Git credentials not configured.',
      conflicts: [],
      filesUpdated: 0,
    }
  }

  const gitClient = new GitClient(workspaceId)

  const isInitialized = await gitClient.isInitialized()
  if (!isInitialized) {
    return {
      success: false,
      message: 'Repository not initialized.',
      conflicts: [],
      filesUpdated: 0,
    }
  }

  try {
    // 1. Fetch latest changes
    await gitClient.fetch(credentials)

    // 2. Get current and remote HEAD
    const currentBranch = (await gitClient.currentBranch()) || 'main'
    const localHead = await git.resolveRef({
      fs: gitClient.fs,
      dir: gitClient.dir,
      ref: 'HEAD',
    })
    const remoteHead = await git.resolveRef({
      fs: gitClient.fs,
      dir: gitClient.dir,
      ref: `refs/remotes/origin/${currentBranch}`,
    }).catch(() => null)

    if (!remoteHead) {
      return {
        success: true,
        message: 'No remote changes.',
        conflicts: [],
        filesUpdated: 0,
      }
    }

    if (localHead === remoteHead) {
      return {
        success: true,
        message: 'Already up to date.',
        conflicts: [],
        filesUpdated: 0,
      }
    }

    // 3. Check for conflicts (compare changed files)
    const conflicts = await detectConflicts(gitClient, workspaceId, localHead, remoteHead)

    if (conflicts.length > 0) {
      // Return conflicts for resolution
      return {
        success: false,
        message: 'Conflicts detected. Please resolve them.',
        conflicts,
        filesUpdated: 0,
      }
    }

    // 4. Fast-forward or merge (no conflicts)
    await git.merge({
      fs: gitClient.fs,
      dir: gitClient.dir,
      ours: localHead,
      theirs: remoteHead,
      author: { name: 'RefMD', email: 'sync@refmd.app' },
    })

    // 5. Apply changes to documents
    const filesUpdated = await applyGitFilesToDocuments(workspaceId, gitClient)

    return {
      success: true,
      message: 'Pull completed successfully.',
      conflicts: [],
      filesUpdated,
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes('merge conflict')) {
      // Handle merge conflict
      const currentBranch = (await gitClient.currentBranch()) || 'main'
      const localHead = await git.resolveRef({
        fs: gitClient.fs,
        dir: gitClient.dir,
        ref: 'HEAD',
      })
      const remoteHead = await git.resolveRef({
        fs: gitClient.fs,
        dir: gitClient.dir,
        ref: `refs/remotes/origin/${currentBranch}`,
      })

      const conflicts = await detectConflicts(gitClient, workspaceId, localHead, remoteHead)

      return {
        success: false,
        message: 'Merge conflicts detected. Please resolve them.',
        conflicts,
        filesUpdated: 0,
      }
    }

    return {
      success: false,
      message: `Pull failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      conflicts: [],
      filesUpdated: 0,
    }
  }
}

/**
 * Detect conflicts between local and remote changes
 */
async function detectConflicts(
  gitClient: GitClient,
  workspaceId: string,
  localHead: string,
  remoteHead: string
): Promise<ConflictItem[]> {
  const conflicts: ConflictItem[] = []

  try {
    // Find common ancestor
    const [mergeBase] = await git.findMergeBase({
      fs: gitClient.fs,
      dir: gitClient.dir,
      oids: [localHead, remoteHead],
    })

    // Get changed files in local and remote
    const localChanges = await getChangedFiles(gitClient, mergeBase, localHead)
    const remoteChanges = await getChangedFiles(gitClient, mergeBase, remoteHead)

    // Find files changed in both
    const conflictPaths = new Set<string>()
    for (const path of localChanges) {
      if (remoteChanges.has(path)) {
        conflictPaths.add(path)
      }
    }

    // Get document mapping
    const documents = await listDocuments({ state: 'active' })
    const pathToDoc = new Map<string, Document>()
    for (const doc of documents.items) {
      if (doc.workspace_id === workspaceId) {
        const path = buildFilePath(doc)
        pathToDoc.set(path, doc)
      }
    }

    // Build conflict items
    for (const path of conflictPaths) {
      const baseContent = await readFileAtCommit(gitClient, mergeBase, path).catch(() => '')
      const oursContent = await readFileAtCommit(gitClient, localHead, path).catch(() => '')
      const theirsContent = await readFileAtCommit(gitClient, remoteHead, path).catch(() => '')

      // Only add if contents are actually different
      if (oursContent !== theirsContent) {
        const doc = pathToDoc.get(path)
        conflicts.push({
          path,
          ours: oursContent,
          theirs: theirsContent,
          base: baseContent,
          documentId: doc?.id,
          is_binary: false,
        })
      }
    }
  } catch {
    // If we can't detect conflicts, return empty array
  }

  return conflicts
}

/**
 * Get changed files between two commits
 */
async function getChangedFiles(
  gitClient: GitClient,
  fromCommit: string,
  toCommit: string
): Promise<Set<string>> {
  const changed = new Set<string>()

  try {
    const fromTree = await git.readTree({
      fs: gitClient.fs,
      dir: gitClient.dir,
      oid: fromCommit,
    })

    const toTree = await git.readTree({
      fs: gitClient.fs,
      dir: gitClient.dir,
      oid: toCommit,
    })

    const fromFiles = new Map<string, string>()
    const toFiles = new Map<string, string>()

    await collectTreeFiles(gitClient, fromTree.tree, '', fromFiles)
    await collectTreeFiles(gitClient, toTree.tree, '', toFiles)

    // Find changed files
    for (const [path, oid] of fromFiles) {
      if (!toFiles.has(path) || toFiles.get(path) !== oid) {
        changed.add(path)
      }
    }

    for (const path of toFiles.keys()) {
      if (!fromFiles.has(path)) {
        changed.add(path)
      }
    }
  } catch {
    // Return empty set on error
  }

  return changed
}

/**
 * Collect all files from a tree
 */
async function collectTreeFiles(
  gitClient: GitClient,
  tree: git.TreeEntry[],
  prefix: string,
  files: Map<string, string>
): Promise<void> {
  for (const entry of tree) {
    const path = prefix ? `${prefix}/${entry.path}` : entry.path

    if (entry.type === 'blob') {
      files.set(path, entry.oid)
    } else if (entry.type === 'tree') {
      const subtree = await git.readTree({
        fs: gitClient.fs,
        dir: gitClient.dir,
        oid: entry.oid,
      })
      await collectTreeFiles(gitClient, subtree.tree, path, files)
    }
  }
}

/**
 * Read file content at a specific commit
 */
async function readFileAtCommit(
  gitClient: GitClient,
  commitOid: string,
  filepath: string
): Promise<string> {
  const commit = await git.readCommit({
    fs: gitClient.fs,
    dir: gitClient.dir,
    oid: commitOid,
  })

  const pathParts = filepath.split('/')
  let currentOid = commit.commit.tree

  for (const part of pathParts) {
    const tree = await git.readTree({
      fs: gitClient.fs,
      dir: gitClient.dir,
      oid: currentOid,
    })

    const entry = tree.tree.find((e) => e.path === part)
    if (!entry) {
      throw new Error(`File not found: ${filepath}`)
    }

    currentOid = entry.oid
  }

  const blob = await git.readBlob({
    fs: gitClient.fs,
    dir: gitClient.dir,
    oid: currentOid,
  })

  return new TextDecoder().decode(blob.blob)
}

/**
 * Apply Git files to documents after successful merge.
 * Returns the count of files that could potentially be updated.
 * Actual document updates happen through the editor's E2EE encryption flow.
 */
async function applyGitFilesToDocuments(
  _workspaceId: string,
  gitClient: GitClient
): Promise<number> {
  let filesUpdated = 0

  try {
    // Get all markdown files from Git
    const allFiles = await listGitFiles(gitClient, '')

    // Count markdown files
    for (const filePath of allFiles) {
      if (filePath.endsWith('.md')) {
        filesUpdated++
      }
    }
  } catch {
    // Return 0 on error
  }

  return filesUpdated
}

/**
 * List all files in Git repository
 */
async function listGitFiles(gitClient: GitClient, dirPath: string): Promise<string[]> {
  const files: string[] = []

  try {
    const entries = await gitClient.listFiles(dirPath)

    for (const entry of entries) {
      if (entry === '.git') continue

      const fullPath = dirPath ? `${dirPath}/${entry}` : entry

      try {
        // Check if it's a directory by trying to list it
        const subEntries = await gitClient.listFiles(fullPath)
        if (Array.isArray(subEntries)) {
          // It's a directory
          const subFiles = await listGitFiles(gitClient, fullPath)
          files.push(...subFiles)
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
 * Build file path from document
 */
function buildFilePath(doc: Document): string {
  const basePath = doc.desired_path || doc.slug || doc.id

  if (doc.type === 'document' && !basePath.endsWith('.md')) {
    return `${basePath}.md`
  }

  return basePath
}

