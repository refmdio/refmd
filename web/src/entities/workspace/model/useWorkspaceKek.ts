/**
 * Hook for fetching and caching workspace KEK
 *
 * Thin React wrapper around kek-service.
 * Uses module-level promise deduplication to prevent race conditions
 * (e.g. React Strict Mode double-mount creating two different KEKs).
 */

import type { DeviceKeyPair } from '@/shared/lib/crypto'
import { useAsyncData } from '@/shared/hooks'
import { fetchOrCreateKek } from '../lib/kek-service'

export interface UseWorkspaceKekResult {
  kek: Uint8Array | null
  isLoading: boolean
  error: Error | null
}

/**
 * Hook to fetch and cache workspace KEK
 *
 * @param workspaceId Workspace ID
 * @param userId User ID (from AuthContext)
 * @param deviceId Current device ID (from AuthContext)
 * @param deviceKeys Current device key pair (from AuthContext)
 * @param umk User Master Key (for UMK backup restore/save)
 */
export function useWorkspaceKek(
  workspaceId: string | null | undefined,
  userId: string | null | undefined,
  deviceId: string | null | undefined,
  deviceKeys: DeviceKeyPair | null | undefined,
  umk: Uint8Array | null | undefined
): UseWorkspaceKekResult {
  const { data: kek, isLoading, error } = useAsyncData(
    () => fetchOrCreateKek(workspaceId!, userId!, deviceId!, deviceKeys!, umk),
    [workspaceId, userId, deviceId, deviceKeys, umk],
  )

  return { kek, isLoading, error }
}
