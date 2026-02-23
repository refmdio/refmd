/**
 * Create Invitation Hook
 *
 * Encapsulates invitation creation business logic: KEK fetching,
 * token generation, encryption, and API call.
 * Extracted from InviteDialog to follow FSD model/ui separation.
 */

import { useState, useCallback } from 'react'
import { workspaceApi, encryptionApi } from '@/shared/api'
import { base64UrlEncode, type DeviceKeyPair } from '@/shared/lib/crypto'
import {
  fetchOrCreateKek,
  generateInvitationToken,
  encryptKekForInvitation,
} from '@/entities/workspace'

export interface CreateInvitationParams {
  workspaceId: string
  roleId: string | null
  email: string
  expiresInDays: number
  /** Authenticated user context */
  userId: string
  deviceId: string
  deviceKeys: DeviceKeyPair
  umk: Uint8Array | null
}

export interface CreateInvitationResult {
  link: string
}

export function useCreateInvitation() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const create = useCallback(
    async (params: CreateInvitationParams): Promise<CreateInvitationResult | null> => {
      setLoading(true)
      setError(null)

      try {
        // 1. Generate invitation ID and token
        // IMPORTANT: invitationId is used in AAD for KEK encryption (encryptKekForInvitation).
        // Must be canonical lowercase-hyphenated UUID to match server-side Uuid::to_string().
        const invitationId = crypto.randomUUID().toLowerCase()
        const { token, tokenHash, tokenPrefix } = generateInvitationToken()

        // 2. Fetch or create KEK
        const kek = await fetchOrCreateKek(
          params.workspaceId,
          params.userId,
          params.deviceId,
          params.deviceKeys,
          params.umk,
        )

        // 3. Get current KEK version from the KekBackup endpoint
        const backupResp = await encryptionApi.getWorkspaceKekBackup(params.workspaceId)
        const keyVersion = backupResp.key_version

        // 4. Encrypt KEK for invitation
        const { encryptedKek, nonce } = encryptKekForInvitation(
          kek,
          token,
          params.workspaceId,
          invitationId,
          keyVersion,
        )

        // 5. Calculate expiration
        const expiresAt = new Date()
        expiresAt.setDate(expiresAt.getDate() + params.expiresInDays)

        // 6. Create invitation via API
        await workspaceApi.createInvitation(params.workspaceId, {
          invitation_id: invitationId,
          token_hash: tokenHash,
          token_prefix: tokenPrefix,
          role_id: params.roleId,
          invited_email: params.email,
          encrypted_kek: base64UrlEncode(encryptedKek),
          kek_nonce: base64UrlEncode(nonce),
          kek_version: keyVersion,
          expires_at: expiresAt.toISOString(),
        })

        // 7. Generate invitation link
        const link = `${window.location.origin}/invite#token=${base64UrlEncode(token)}`
        return { link }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to create invitation')
        return null
      } finally {
        setLoading(false)
      }
    },
    [],
  )

  return { loading, error, setError, create }
}
