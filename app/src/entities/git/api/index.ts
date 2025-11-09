import {
  createOrUpdateConfig as apiCreateOrUpdateConfig,
  deinitRepository as apiDeinitRepository,
  getChanges as apiGetChanges,
  getCommitDiff as apiGetCommitDiff,
  getConfig as apiGetConfig,
  getHistory as apiGetHistory,
  getStatus as apiGetStatus,
  getWorkingDiff as apiGetWorkingDiff,
  ignoreDocument as apiIgnoreDocument,
  ignoreFolder as apiIgnoreFolder,
  initRepository as apiInitRepository,
  syncNow as apiSyncNow,
} from '@/shared/api'
import type { GitChangesResponse, GitHistoryResponse, GitStatus, TextDiffResult } from '@/shared/api'

export const gitKeys = {
  all: ['git'] as const,
  config: () => ['git','config'] as const,
  status: () => ['git','status'] as const,
  changes: () => ['git','changes'] as const,
  history: () => ['git','history'] as const,
  diffWorking: () => ['git','diff','working'] as const,
  diffCommits: (from: string, to: string) => ['git','diff','commits', { from, to }] as const,
}

// Use-case oriented helpers (thin wrappers) to decouple features from raw service signatures
export async function fetchStatus(): Promise<GitStatus> {
  return apiGetStatus()
}

export async function fetchChanges(): Promise<GitChangesResponse> {
  return apiGetChanges()
}

export async function fetchHistory(): Promise<GitHistoryResponse> {
  return apiGetHistory()
}

export async function fetchCommitDiff(from: string, to: string): Promise<TextDiffResult[]> {
  return apiGetCommitDiff({ _from: from, to })
}

export {
  apiGetStatus as getStatus,
  apiGetConfig as getConfig,
  apiGetChanges as getChanges,
  apiGetHistory as getHistory,
  apiGetWorkingDiff as getWorkingDiff,
  apiGetCommitDiff as getCommitDiff,
  apiCreateOrUpdateConfig as createOrUpdateConfig,
  apiDeinitRepository as deinitRepository,
  apiInitRepository as initRepository,
  apiSyncNow as syncNow,
  apiIgnoreDocument as ignoreDocument,
  apiIgnoreFolder as ignoreFolder,
}
