import { useQuery } from '@tanstack/react-query'

import {
  getPublicByWorkspaceAndId as apiGetPublicByWorkspaceAndId,
  getPublicContentByWorkspaceAndId as apiGetPublicContentByWorkspaceAndId,
  getPublishStatus as apiGetPublishStatus,
  getWorkspacePermissions as apiGetWorkspacePermissions,
  listWorkspacePublicDocuments as apiListWorkspacePublicDocuments,
  publishDocument as apiPublishDocument,
  unpublishDocument as apiUnpublishDocument,
} from '@/shared/api'
import type { PublicDocumentSummary } from '@/shared/api'

export const publicKeys = {
  all: ['public'] as const,
  byWorkspace: (slug: string) => ['public', 'workspace', slug] as const,
  status: (id: string) => ['public', 'status', id] as const,
}

export const workspacePublicDocsQuery = (slug: string) => ({
  queryKey: publicKeys.byWorkspace(slug),
  queryFn: () => apiListWorkspacePublicDocuments({ slug }) as Promise<PublicDocumentSummary[]>,
  enabled: !!slug,
})

export function useWorkspacePublicDocuments(slug?: string) {
  return useQuery(workspacePublicDocsQuery(slug || ''))
}

// Use-case oriented helpers
export async function listWorkspacePublicDocuments(slug: string) {
  return apiListWorkspacePublicDocuments({ slug })
}

export async function getPublicByWorkspaceAndId(slug: string, id: string) {
  return apiGetPublicByWorkspaceAndId({ slug, id })
}

export async function getPublicContentByWorkspaceAndId(slug: string, id: string) {
  return apiGetPublicContentByWorkspaceAndId({ slug, id })
}

export async function publishDocument(id: string) {
  return apiPublishDocument({ id })
}

export async function unpublishDocument(id: string) {
  return apiUnpublishDocument({ id })
}

export async function getPublishStatus(id: string) {
  return apiGetPublishStatus({ id })
}

export async function getWorkspacePermissions(workspaceId: string) {
  return apiGetWorkspacePermissions({ id: workspaceId })
}
