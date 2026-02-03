/**
 * Hook for fetching and caching workspace KEK
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { encryptionApi, ApiError } from '@/shared/api'
import { base64UrlDecode, base64UrlEncode } from '@/shared/lib/crypto'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildAad, SIGNATURE_PROTOCOL, AAD_PURPOSE } from '@/shared/lib/crypto/aad'

export interface UseWorkspaceKekResult {
  kek: Uint8Array | null
  isLoading: boolean
  error: Error | null
  refresh: () => Promise<void>
}

// In-memory cache for KEKs (workspace_id -> KEK)
const kekCache = new Map<string, Uint8Array>()

/**
 * Build AAD for KEK wrap (Phase 1C: UMK-wrapped KEK)
 */
function buildKekWrapAad(workspaceId: string, userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.KEK_WRAP,
    workspace_id: workspaceId,
    user_id: userId,
  })
}

/**
 * Decrypt KEK using UMK
 */
function unwrapKek(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string
): Uint8Array {
  const aad = buildKekWrapAad(workspaceId, userId)
  const cipher = xchacha20poly1305(umk, nonce, aad)
  return cipher.decrypt(encryptedKek)
}

/**
 * Encrypt KEK using UMK
 */
function wrapKek(
  kek: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string
): { encryptedKek: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24)
  const aad = buildKekWrapAad(workspaceId, userId)
  const cipher = xchacha20poly1305(umk, nonce, aad)
  const encryptedKek = cipher.encrypt(kek)
  return { encryptedKek, nonce }
}

/**
 * Hook to fetch and cache workspace KEK
 *
 * @param workspaceId Workspace ID
 * @param umk User Master Key (from AuthContext)
 * @param userId User ID (from AuthContext)
 */
export function useWorkspaceKek(
  workspaceId: string | null | undefined,
  umk: Uint8Array | null | undefined,
  userId: string | null | undefined
): UseWorkspaceKekResult {
  const [kek, setKek] = useState<Uint8Array | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const fetchingRef = useRef(false)

  const fetchKek = useCallback(async () => {
    if (!workspaceId || !umk || !userId) {
      setKek(null)
      return
    }

    // Check cache first
    const cached = kekCache.get(workspaceId)
    if (cached) {
      setKek(cached)
      return
    }

    // Prevent concurrent fetches
    if (fetchingRef.current) {
      return
    }

    fetchingRef.current = true
    setIsLoading(true)
    setError(null)

    try {
      // Try to get existing KEK from server
      const response = await encryptionApi.getWorkspaceKey(workspaceId)
      const encryptedKek = base64UrlDecode(response.encrypted_kek)
      const nonce = base64UrlDecode(response.nonce)

      // Decrypt KEK with UMK
      const decryptedKek = unwrapKek(encryptedKek, nonce, umk, workspaceId, userId)

      // Cache and set
      kekCache.set(workspaceId, decryptedKek)
      setKek(decryptedKek)
    } catch (err) {
      // If 404, generate new KEK
      if (err instanceof ApiError && err.status === 404) {
        try {
          // Generate new KEK (32 bytes)
          const newKek = randomBytes(32)

          // Wrap with UMK
          const { encryptedKek, nonce } = wrapKek(newKek, umk, workspaceId, userId)

          // Save to server
          await encryptionApi.saveWorkspaceKey(workspaceId, {
            encrypted_kek: base64UrlEncode(encryptedKek),
            nonce: base64UrlEncode(nonce),
            is_active: true,
          })

          // Cache and set
          kekCache.set(workspaceId, newKek)
          setKek(newKek)
        } catch (saveErr) {
          setError(saveErr instanceof Error ? saveErr : new Error('Failed to create workspace key'))
        }
      } else {
        setError(err instanceof Error ? err : new Error('Failed to fetch workspace key'))
      }
    } finally {
      setIsLoading(false)
      fetchingRef.current = false
    }
  }, [workspaceId, umk, userId])

  // Fetch on mount and when dependencies change
  useEffect(() => {
    fetchKek()
  }, [fetchKek])

  return {
    kek,
    isLoading,
    error,
    refresh: fetchKek,
  }
}

/**
 * Clear KEK cache for a workspace (call on logout or workspace change)
 */
export function clearKekCache(workspaceId?: string) {
  if (workspaceId) {
    kekCache.delete(workspaceId)
  } else {
    kekCache.clear()
  }
}
