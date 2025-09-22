import { GitService } from '@/shared/api'
import type { GitDiffResult, GitChangesResponse, GitHistoryResponse, GitStatus } from '@/shared/api'

export const gitKeys = {
  all: ['git'] as const,
  config: () => ['git','config'] as const,
  status: () => ['git','status'] as const,
  changes: () => ['git','changes'] as const,
  history: () => ['git','history'] as const,
  diffWorking: () => ['git','diff','working'] as const,
  diffCommits: (from: string, to: string) => ['git','diff','commits', { from, to }] as const,
}

export { GitService }

// Use-case oriented helpers (thin wrappers) to decouple features from raw service signatures
export async function fetchStatus(): Promise<GitStatus> {
  return GitService.getStatus()
}

export async function fetchChanges(): Promise<GitChangesResponse> {
  return GitService.getChanges()
}

export async function fetchHistory(): Promise<GitHistoryResponse> {
  return GitService.getHistory()
}

export async function fetchCommitDiff(from: string, to: string): Promise<GitDiffResult[]> {
  return GitService.getCommitDiff({ from, to })
}
