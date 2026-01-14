/**
 * Git API layer - only exports server-side config API.
 * All Git operations (status, sync, pull, history, etc.) are now handled client-side
 * via @/features/git-sync for E2EE compatibility.
 */
import {
  createOrUpdateConfig as apiCreateOrUpdateConfig,
  deleteConfig as apiDeleteConfig,
  getConfig as apiGetConfig,
} from '@/shared/api'
import type {
  CreateGitConfigRequest,
  GitConfigResponse,
} from '@/shared/api'

export const gitKeys = {
  all: ['git'] as const,
  config: () => ['git', 'config'] as const,
}

export {
  apiGetConfig as getConfig,
  apiCreateOrUpdateConfig as createOrUpdateConfig,
  apiDeleteConfig as deleteConfig,
}

export type { CreateGitConfigRequest, GitConfigResponse }
