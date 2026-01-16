import { useQuery } from '@tanstack/react-query'

import { securityStatusQuery, needsMigrationQuery } from '@/entities/user'

export interface SecurityStatus {
  /** Whether E2EE setup has been completed */
  isSetupComplete: boolean
  /** Whether data migration is needed (existing user) */
  needsMigration: boolean
}

interface UseSecurityStatusOptions {
  enabled?: boolean
}

interface UseSecurityStatusResult {
  data: SecurityStatus | undefined
  isLoading: boolean
  error: Error | null
  refetch: () => void
}

/**
 * Hook to fetch and combine security status information.
 * Combines E2EE status and migration status into a single interface.
 */
export function useSecurityStatus(options?: UseSecurityStatusOptions): UseSecurityStatusResult {
  const enabled = options?.enabled ?? true
  const statusQuery = useQuery({ ...securityStatusQuery(), enabled })
  const migrationQuery = useQuery({ ...needsMigrationQuery(), enabled })

  const isLoading = statusQuery.isLoading || migrationQuery.isLoading
  const error = statusQuery.error ?? migrationQuery.error

  const data: SecurityStatus | undefined =
    statusQuery.data && migrationQuery.data
      ? {
          isSetupComplete: statusQuery.data.isSetupCompleted,
          needsMigration: migrationQuery.data.needsMigration,
        }
      : undefined

  const refetch = () => {
    statusQuery.refetch()
    migrationQuery.refetch()
  }

  return {
    data,
    isLoading,
    error: error as Error | null,
    refetch,
  }
}

/**
 * Hook to check if security setup is required.
 * Returns true if setup is not complete.
 */
export function useNeedsSecuritySetup(): {
  needsSetup: boolean | undefined
  isLoading: boolean
} {
  const { data, isLoading } = useSecurityStatus()

  return {
    needsSetup: data ? !data.isSetupComplete : undefined,
    isLoading,
  }
}
