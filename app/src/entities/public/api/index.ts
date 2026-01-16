import { useQuery } from '@tanstack/react-query'

import {
  getPublicByWorkspaceAndId as apiGetPublicByWorkspaceAndId,
  getPublicContentByWorkspaceAndId as apiGetPublicContentByWorkspaceAndId,
  getPublicFile as apiGetPublicFile,
  getPublishStatus as apiGetPublishStatus,
  getWorkspacePermissions as apiGetWorkspacePermissions,
  listPublicFiles as apiListPublicFiles,
  listWorkspacePublicDocuments as apiListWorkspacePublicDocuments,
  publishDocument as apiPublishDocument,
  unpublishDocument as apiUnpublishDocument,
  uploadPublicFile as apiUploadPublicFile,
} from '@/shared/api'
import type { PublicDocumentSummary, PublicFile } from '@/shared/api'

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

export type PublishDocumentOptions = {
  plaintextTitle?: string
  plaintextContent?: string
}

export async function publishDocument(id: string, options?: PublishDocumentOptions) {
  return apiPublishDocument({
    id,
    requestBody: options ? {
      plaintextTitle: options.plaintextTitle,
      plaintextContent: options.plaintextContent,
    } : undefined,
  })
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

// --- Public file helpers ---

export type UploadPublicFileOptions = {
  originalFilename: string
  logicalFilename: string
  mimeType: string
  content: string // Base64 encoded
}

export async function uploadPublicFile(
  docId: string,
  fileId: string,
  options: UploadPublicFileOptions
) {
  return apiUploadPublicFile({
    id: docId,
    fileId,
    requestBody: options,
  })
}

export async function listPublicFiles(slug: string, docId: string): Promise<PublicFile[]> {
  return apiListPublicFiles({ slug, id: docId }) as Promise<PublicFile[]>
}

export async function getPublicFile(slug: string, docId: string, filename: string) {
  return apiGetPublicFile({ slug, id: docId, filename })
}

export type { PublicFile }
