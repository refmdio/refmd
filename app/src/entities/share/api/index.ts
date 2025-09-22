import { useQuery } from '@tanstack/react-query'

import { SharingService } from '@/shared/api'
import type { ActiveShareItem } from '@/shared/api'

export const shareKeys = {
  all: ['shares'] as const,
  byDoc: (id: string) => ['shares','byDoc', id] as const,
  active: () => ['shares','active'] as const,
  applicable: (docId: string) => ['shares','applicable', docId] as const,
}

export { SharingService }

export const activeSharesQuery = () => ({
  queryKey: shareKeys.active(),
  queryFn: () => SharingService.listActiveShares() as Promise<ActiveShareItem[]>,
})

export function useActiveShares() {
  return useQuery(activeSharesQuery())
}

// Use-case oriented helpers
export async function listActiveShares() {
  return SharingService.listActiveShares()
}
export async function validateShareToken(token: string) {
  return SharingService.validateShareToken({ token })
}

export async function browseShare(token: string) {
  return SharingService.browseShare({ token })
}

export async function listDocumentShares(id: string) {
  return SharingService.listDocumentShares({ id })
}

export async function createShare(input: { document_id: string; permission: string; expires_at?: string | null; scope?: 'document' | 'folder'; parent_share_id?: string | null }) {
  return SharingService.createShare({ requestBody: input as any })
}

export async function deleteShare(token: string) {
  return SharingService.deleteShare({ token })
}
