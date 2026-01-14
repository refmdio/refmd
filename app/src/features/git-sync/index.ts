export { default as GitSyncButton } from './ui/git-sync-button'
export { default as GitHistoryDialog } from './ui/git-history-dialog'
export { default as GitChangesDialog } from './ui/git-changes-dialog'
export { default as GitPullDialog } from './ui/git-pull-dialog'
export * from './ui/commit-diff-panel'
export * from './ui/working-diff-panel'

// E2EE Git sync - Core
export { GitClient } from './lib/git-client'
export {
  saveGitCredentials,
  loadGitCredentials,
  deleteGitCredentials,
  hasGitCredentials,
  type GitCredentials,
} from './lib/git-credentials'

// E2EE Git sync - Sync
export {
  syncWorkspaceToGit,
  initGitRepository,
  getGitStatus,
  getGitHistory,
  type SyncOptions,
  type SyncResult,
} from './lib/sync'

// E2EE Git sync - Pull
export {
  pullFromGit,
  type PullResult,
  type ConflictItem,
} from './lib/pull'

// E2EE Git sync - History & Diff
export {
  getHistory,
  getWorkingDiff,
  getCommitDiff,
  type GitCommitItem,
  type TextDiffResult,
  type DiffLine,
  type TextDiffLineType,
} from './lib/history'

// E2EE Git sync - Conflict Resolution
export {
  resolveConflict,
  finalizeConflictResolution,
  abortConflictResolution,
  generateMergePreview,
  type ConflictResolution,
} from './lib/conflict-resolver'

// E2EE Git sync - Import
export {
  importFromGit,
  getImportableFiles,
  readImportFile,
  clearImportedRepository,
  type ImportResult,
  type ImportProgress,
} from './lib/import'

// E2EE Git sync - Dirty calculation
export {
  calculateDirtyFiles,
  type DirtyFile,
} from './lib/dirty-calculator'
