/**
 * Conflict Resolver for E2EE Git Sync
 *
 * Handles resolving merge conflicts client-side.
 */

import * as git from 'isomorphic-git'
import { GitClient } from './git-client'
import { loadGitCredentials } from './git-credentials'
import { getKeyManager } from '@/features/security'

export interface ConflictResolution {
  path: string
  choice: 'ours' | 'theirs' | 'custom'
  customContent?: string
}

/**
 * Resolve a single conflict
 */
export async function resolveConflict(
  workspaceId: string,
  resolution: ConflictResolution,
  oursContent: string,
  theirsContent: string
): Promise<void> {
  const gitClient = new GitClient(workspaceId)

  let content: string
  switch (resolution.choice) {
    case 'ours':
      content = oursContent
      break
    case 'theirs':
      content = theirsContent
      break
    case 'custom':
      if (!resolution.customContent) {
        throw new Error('Custom content required for custom resolution')
      }
      content = resolution.customContent
      break
    default:
      throw new Error(`Unknown resolution choice: ${resolution.choice}`)
  }

  // Write resolved content to file
  await gitClient.writeFile(resolution.path, content)

  // Stage the resolved file
  await gitClient.add(resolution.path)
}

/**
 * Finalize conflict resolution by creating a merge commit
 */
export async function finalizeConflictResolution(
  workspaceId: string,
  commitMessage?: string
): Promise<{ success: boolean; message: string; commitSha?: string }> {
  const keyManager = getKeyManager()
  if (!keyManager.isUnlocked) {
    return {
      success: false,
      message: 'E2EE is locked. Please unlock first.',
    }
  }

  const credentials = await loadGitCredentials(workspaceId)
  if (!credentials) {
    return {
      success: false,
      message: 'Git credentials not configured.',
    }
  }

  const gitClient = new GitClient(workspaceId)

  try {
    // Create merge commit
    const message = commitMessage || 'Merge remote changes (resolved conflicts)'
    const commitSha = await gitClient.commit(message)

    // Push to remote
    await gitClient.push(credentials)

    return {
      success: true,
      message: 'Conflicts resolved and pushed successfully.',
      commitSha,
    }
  } catch (error) {
    return {
      success: false,
      message: `Failed to finalize: ${error instanceof Error ? error.message : 'Unknown error'}`,
    }
  }
}

/**
 * Abort conflict resolution (reset to HEAD)
 */
export async function abortConflictResolution(
  workspaceId: string
): Promise<{ success: boolean; message: string }> {
  const gitClient = new GitClient(workspaceId)

  try {
    // Reset to HEAD
    const currentHead = await git.resolveRef({
      fs: gitClient.fs,
      dir: gitClient.dir,
      ref: 'HEAD',
    })

    await git.checkout({
      fs: gitClient.fs,
      dir: gitClient.dir,
      ref: currentHead,
      force: true,
    })

    return {
      success: true,
      message: 'Conflict resolution aborted.',
    }
  } catch (error) {
    return {
      success: false,
      message: `Failed to abort: ${error instanceof Error ? error.message : 'Unknown error'}`,
    }
  }
}

/**
 * Generate a three-way merge preview
 */
export function generateMergePreview(
  base: string,
  ours: string,
  theirs: string
): string {
  const baseLines = base.split('\n')
  const oursLines = ours.split('\n')
  const theirsLines = theirs.split('\n')

  // Simple three-way merge visualization
  const result: string[] = []

  const maxLen = Math.max(baseLines.length, oursLines.length, theirsLines.length)

  for (let i = 0; i < maxLen; i++) {
    const baseLine = baseLines[i]
    const ourLine = oursLines[i]
    const theirLine = theirsLines[i]

    if (ourLine === theirLine) {
      // Same in both - use it
      if (ourLine !== undefined) {
        result.push(ourLine)
      }
    } else if (ourLine === baseLine) {
      // Changed only in theirs - use theirs
      if (theirLine !== undefined) {
        result.push(theirLine)
      }
    } else if (theirLine === baseLine) {
      // Changed only in ours - use ours
      if (ourLine !== undefined) {
        result.push(ourLine)
      }
    } else {
      // Changed in both - conflict
      result.push('<<<<<<< ours')
      if (ourLine !== undefined) {
        result.push(ourLine)
      }
      result.push('=======')
      if (theirLine !== undefined) {
        result.push(theirLine)
      }
      result.push('>>>>>>> theirs')
    }
  }

  return result.join('\n')
}
