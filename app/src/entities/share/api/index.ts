import { useQuery } from '@tanstack/react-query'

import {
  browseShare as apiBrowseShare,
  createShare as apiCreateShare,
  createShareMount as apiCreateShareMount,
  deleteShare as apiDeleteShare,
  deleteShareMount as apiDeleteShareMount,
  listActiveShares as apiListActiveShares,
  listDocumentShares as apiListDocumentShares,
  listShareMounts as apiListShareMounts,
  validateShareToken as apiValidateShareToken,
} from '@/shared/api'
import type { ActiveShareItem, ShareMountItem } from '@/shared/api'

export const shareKeys = {
  all: ['shares'] as const,
  byDoc: (id: string) => ['shares','byDoc', id] as const,
  active: () => ['shares','active'] as const,
  applicable: (docId: string) => ['shares','applicable', docId] as const,
  mounts: () => ['shares','mounts'] as const,
}

export const activeSharesQuery = () => ({
  queryKey: shareKeys.active(),
  queryFn: () => apiListActiveShares() as Promise<ActiveShareItem[]>,
})

export const shareMountsQuery = () => ({
  queryKey: shareKeys.mounts(),
  queryFn: () => apiListShareMounts() as Promise<ShareMountItem[]>,
})

export function useActiveShares() {
  return useQuery(activeSharesQuery())
}

export function useShareMounts() {
  return useQuery(shareMountsQuery())
}

// Use-case oriented helpers
export async function listActiveShares() {
  return apiListActiveShares()
}
export async function validateShareToken(token: string) {
  return apiValidateShareToken({ token })
}

export async function browseShare(token: string) {
  return apiBrowseShare({ token })
}

export async function listDocumentShares(id: string) {
  return apiListDocumentShares({ id })
}

export async function createShare(input: { document_id: string; permission: string; expires_at?: string | null; scope?: 'document' | 'folder'; parent_share_id?: string | null }) {
  return apiCreateShare({ requestBody: input as any })
}

export async function deleteShare(token: string) {
  return apiDeleteShare({ token })
}

export async function listShareMounts() {
  return apiListShareMounts()
}

export async function createShareMount(input: { token: string; parent_folder_id?: string | null }) {
  return apiCreateShareMount({ requestBody: input })
}

export async function deleteShareMount(id: string) {
  return apiDeleteShareMount({ id })
}
