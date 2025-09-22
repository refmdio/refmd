import { useQuery } from '@tanstack/react-query'

import { PublicDocumentsService } from '@/shared/api'
import type { PublicDocumentSummary } from '@/shared/api'

export const publicKeys = {
  all: ['public'] as const,
  byUser: (name: string) => ['public','byUser', name] as const,
  status: (id: string) => ['public','status', id] as const,
}

export { PublicDocumentsService }

export const userPublicDocsQuery = (name: string) => ({
  queryKey: publicKeys.byUser(name),
  queryFn: () => PublicDocumentsService.listUserPublicDocuments({ name }) as Promise<PublicDocumentSummary[]>,
  enabled: !!name,
})

export function useUserPublicDocuments(name?: string) {
  return useQuery(userPublicDocsQuery(name || ''))
}

// Use-case oriented helpers
export async function listUserPublicDocuments(name: string) {
  return PublicDocumentsService.listUserPublicDocuments({ name })
}

export async function getPublicByOwnerAndId(name: string, id: string) {
  return PublicDocumentsService.getPublicByOwnerAndId({ name, id })
}

export async function getPublicContentByOwnerAndId(name: string, id: string) {
  return PublicDocumentsService.getPublicContentByOwnerAndId({ name, id })
}

export async function publishDocument(id: string) {
  return PublicDocumentsService.publishDocument({ id })
}

export async function unpublishDocument(id: string) {
  return PublicDocumentsService.unpublishDocument({ id })
}

export async function getPublishStatus(id: string) {
  return PublicDocumentsService.getPublishStatus({ id })
}
