import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  createApiToken as apiCreateApiToken,
  listApiTokens as apiListApiTokens,
  revokeApiToken as apiRevokeApiToken,
} from '@/shared/api'
import type { CreateApiTokenResponse, ListApiTokensResponse } from '@/shared/api'

export const apiTokenKeys = {
  root: ['api-tokens'] as const,
  list: (workspaceId?: string | null) => ['api-tokens', workspaceId ?? 'current'] as const,
}

export const apiTokensQuery = (workspaceId?: string | null) => ({
  queryKey: apiTokenKeys.list(workspaceId),
  queryFn: () => apiListApiTokens() as Promise<ListApiTokensResponse>,
})

type UseApiTokensOptions = {
  enabled?: boolean
  workspaceId?: string | null
}

export function useApiTokens(options?: UseApiTokensOptions) {
  return useQuery({
    ...apiTokensQuery(options?.workspaceId),
    enabled: options?.enabled ?? true,
  })
}

type CreateVariables = { name?: string }

export function useCreateApiToken(options?: {
  workspaceId?: string | null
  onSuccess?: (data: CreateApiTokenResponse, variables: CreateVariables | undefined) => void
  onError?: (error: unknown, variables: CreateVariables | undefined) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (variables?: CreateVariables) =>
      apiCreateApiToken({
        requestBody: {
          name: variables?.name ?? undefined,
        },
      }) as Promise<CreateApiTokenResponse>,
    onSuccess: (data, variables) => {
      qc.invalidateQueries({ queryKey: apiTokenKeys.list(options?.workspaceId) })
      options?.onSuccess?.(data, variables)
    },
    onError: (error, variables) => {
      options?.onError?.(error, variables)
    },
  })
}

export function useRevokeApiToken(options?: {
  workspaceId?: string | null
  onSuccess?: (tokenId: string) => void
  onError?: (error: unknown, tokenId: string) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (tokenId: string) => apiRevokeApiToken({ id: tokenId }) as Promise<void>,
    onSuccess: (_data, tokenId) => {
      qc.invalidateQueries({ queryKey: apiTokenKeys.list(options?.workspaceId) })
      options?.onSuccess?.(tokenId)
    },
    onError: (error, tokenId) => {
      options?.onError?.(error, tokenId)
    },
  })
}

export type ApiToken = ListApiTokensResponse[number]
