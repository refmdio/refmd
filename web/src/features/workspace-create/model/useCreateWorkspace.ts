/**
 * Create Workspace Hook
 *
 * Encapsulates workspace creation logic: API call + best-effort KEK generation.
 * Extracted from CreateWorkspaceDialog to follow FSD model/ui separation.
 */

import { useState, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useQueryClient } from '@tanstack/react-query'
import { workspaceApi } from '@/shared/api'
import { useAuthContext } from '@/shared/context'
import { fetchOrCreateKek } from '@/entities/workspace'

interface UseCreateWorkspaceParams {
  onOpenChange: (open: boolean) => void
}

export function useCreateWorkspace({ onOpenChange }: UseCreateWorkspaceParams) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { auth, device } = useAuthContext()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const create = useCallback(
    async (name: string, description?: string): Promise<boolean> => {
      const trimmed = name.trim()
      if (!trimmed) return false

      setLoading(true)
      setError(null)

      try {
        const desc = description?.trim() || undefined
        const result = await workspaceApi.create({ name: trimmed, description: desc })

        // Best-effort KEK generation -- workspace already exists, so navigate even if this fails.
        // The workspace page will trigger KEK generation via useWorkspaceKek if needed.
        if (auth && device) {
          try {
            await fetchOrCreateKek(
              result.workspace.id,
              auth.userId,
              device.deviceId,
              device.deviceKeys,
              auth.umk,
            )
          } catch {
            // KEK will be created on-demand when the workspace page loads
          }
        }

        await queryClient.invalidateQueries({ queryKey: ['workspaces'] })
        onOpenChange(false)
        navigate({
          to: '/workspace/$workspaceId',
          params: { workspaceId: result.workspace.id },
        })
        return true
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to create workspace',
        )
        return false
      } finally {
        setLoading(false)
      }
    },
    [auth, device, queryClient, onOpenChange, navigate],
  )

  return { loading, error, create }
}
