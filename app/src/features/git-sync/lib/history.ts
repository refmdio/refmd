/**
 * Git History and Diff for E2EE Git Sync
 *
 * Uses isomorphic-git for client-side history and diff operations.
 */

import * as git from 'isomorphic-git'
import type { FsClient } from 'isomorphic-git'
import { GitClient } from './git-client'
import { calculateDirtyFiles } from './dirty-calculator'
import { fetchDecryptedDocumentContent } from './sync'

export interface GitCommitItem {
  hash: string
  message: string
  author_name: string
  author_email: string
  time: string
}

export type TextDiffLineType = 'added' | 'deleted' | 'context'

export interface DiffLine {
  line_type: TextDiffLineType
  content: string
  old_line_number: number | null
  new_line_number: number | null
}

export interface TextDiffResult {
  file_path: string
  diff_lines: DiffLine[]
}

/**
 * Get commit history for workspace
 */
export async function getHistory(workspaceId: string, depth: number = 50): Promise<GitCommitItem[]> {
  const gitClient = new GitClient(workspaceId)

  const isInitialized = await gitClient.isInitialized()
  if (!isInitialized) {
    return []
  }

  try {
    const commits = await gitClient.log(depth)

    return commits.map((commit) => ({
      hash: commit.oid,
      message: commit.commit.message,
      author_name: commit.commit.author.name,
      author_email: commit.commit.author.email,
      time: new Date(commit.commit.author.timestamp * 1000).toISOString(),
    }))
  } catch {
    return []
  }
}

/**
 * Simple line-based diff algorithm
 */
function computeLineDiff(oldContent: string, newContent: string): DiffLine[] {
  const oldLines = oldContent.split('\n')
  const newLines = newContent.split('\n')

  const diffLines: DiffLine[] = []

  // Simple diff: use LCS (Longest Common Subsequence) algorithm
  const lcs = computeLCS(oldLines, newLines)

  let oldIdx = 0
  let newIdx = 0
  let lcsIdx = 0

  while (oldIdx < oldLines.length || newIdx < newLines.length) {
    if (lcsIdx < lcs.length && oldIdx < oldLines.length && oldLines[oldIdx] === lcs[lcsIdx]) {
      // Common line
      if (newIdx < newLines.length && newLines[newIdx] === lcs[lcsIdx]) {
        diffLines.push({
          line_type: 'context',
          content: oldLines[oldIdx],
          old_line_number: oldIdx + 1,
          new_line_number: newIdx + 1,
        })
        oldIdx++
        newIdx++
        lcsIdx++
      } else {
        // Addition in new
        diffLines.push({
          line_type: 'added',
          content: newLines[newIdx],
          old_line_number: null,
          new_line_number: newIdx + 1,
        })
        newIdx++
      }
    } else if (oldIdx < oldLines.length) {
      // Deletion from old
      diffLines.push({
        line_type: 'deleted',
        content: oldLines[oldIdx],
        old_line_number: oldIdx + 1,
        new_line_number: null,
      })
      oldIdx++
    } else if (newIdx < newLines.length) {
      // Addition in new
      diffLines.push({
        line_type: 'added',
        content: newLines[newIdx],
        old_line_number: null,
        new_line_number: newIdx + 1,
      })
      newIdx++
    }
  }

  return diffLines
}

/**
 * Compute Longest Common Subsequence
 */
function computeLCS(a: string[], b: string[]): string[] {
  const m = a.length
  const n = b.length

  // DP table
  const dp: number[][] = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0))

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1])
      }
    }
  }

  // Backtrack to find LCS
  const lcs: string[] = []
  let i = m
  let j = n

  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      lcs.unshift(a[i - 1])
      i--
      j--
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--
    } else {
      j--
    }
  }

  return lcs
}

/**
 * Get working tree diff (uncommitted changes)
 */
export async function getWorkingDiff(workspaceId: string): Promise<TextDiffResult[]> {
  const gitClient = new GitClient(workspaceId)

  const isInitialized = await gitClient.isInitialized()
  if (!isInitialized) {
    return []
  }

  const dirtyFiles = await calculateDirtyFiles(workspaceId, gitClient)

  const diffs: TextDiffResult[] = []

  for (const dirty of dirtyFiles) {
    try {
      let oldContent = ''
      let newContent = ''

      if (dirty.status === 'deleted') {
        oldContent = await gitClient.readFile(dirty.path).catch(() => '')
        newContent = ''
      } else if (dirty.status === 'added') {
        oldContent = ''
        newContent = await fetchDecryptedDocumentContent(dirty.documentId, workspaceId)
      } else {
        oldContent = await gitClient.readFile(dirty.path).catch(() => '')
        newContent = await fetchDecryptedDocumentContent(dirty.documentId, workspaceId)
      }

      diffs.push({
        file_path: dirty.path,
        diff_lines: computeLineDiff(oldContent, newContent),
      })
    } catch {
      // Skip files that can't be diffed
    }
  }

  return diffs
}

/**
 * Get diff between two commits
 */
export async function getCommitDiff(
  workspaceId: string,
  fromCommit: string,
  toCommit: string
): Promise<TextDiffResult[]> {
  const gitClient = new GitClient(workspaceId)

  const isInitialized = await gitClient.isInitialized()
  if (!isInitialized) {
    return []
  }

  try {
    // Get files changed between commits
    const changedFiles = await getChangedFilesBetweenCommits(gitClient, fromCommit, toCommit)

    const diffs: TextDiffResult[] = []

    for (const file of changedFiles) {
      const oldContent = await readFileAtCommit(gitClient, fromCommit, file).catch(() => '')
      const newContent = await readFileAtCommit(gitClient, toCommit, file).catch(() => '')

      diffs.push({
        file_path: file,
        diff_lines: computeLineDiff(oldContent, newContent),
      })
    }

    return diffs
  } catch {
    return []
  }
}

/**
 * Get list of changed files between two commits
 */
async function getChangedFilesBetweenCommits(
  gitClient: GitClient,
  fromCommit: string,
  toCommit: string
): Promise<string[]> {
  const fs = gitClient.fs
  const dir = gitClient.dir

  const fromTree = await git.readTree({
    fs,
    dir,
    oid: fromCommit,
  })

  const toTree = await git.readTree({
    fs,
    dir,
    oid: toCommit,
  })

  const fromFiles = new Map<string, string>()
  const toFiles = new Map<string, string>()

  // Collect files from both trees
  await collectFilesFromTree(fs, dir, fromTree.tree, '', fromFiles)
  await collectFilesFromTree(fs, dir, toTree.tree, '', toFiles)

  // Find changed files
  const changedFiles = new Set<string>()

  for (const [path, oid] of fromFiles) {
    if (!toFiles.has(path) || toFiles.get(path) !== oid) {
      changedFiles.add(path)
    }
  }

  for (const path of toFiles.keys()) {
    if (!fromFiles.has(path)) {
      changedFiles.add(path)
    }
  }

  return Array.from(changedFiles)
}

/**
 * Recursively collect files from a tree
 */
async function collectFilesFromTree(
  fs: FsClient,
  dir: string,
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
        fs,
        dir,
        oid: entry.oid,
      })
      await collectFilesFromTree(fs, dir, subtree.tree, path, files)
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
  const fs = gitClient.fs
  const dir = gitClient.dir

  // Get the commit
  const commit = await git.readCommit({
    fs,
    dir,
    oid: commitOid,
  })

  // Walk the tree to find the file
  const pathParts = filepath.split('/')
  let currentOid = commit.commit.tree

  for (let i = 0; i < pathParts.length; i++) {
    const tree = await git.readTree({
      fs,
      dir,
      oid: currentOid,
    })

    const entry = tree.tree.find((e) => e.path === pathParts[i])
    if (!entry) {
      throw new Error(`File not found: ${filepath}`)
    }

    currentOid = entry.oid
  }

  // Read the blob
  const blob = await git.readBlob({
    fs,
    dir,
    oid: currentOid,
  })

  return new TextDecoder().decode(blob.blob)
}
