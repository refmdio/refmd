import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  archiveDocument as apiArchiveDocument,
  createDocument as apiCreateDocument,
  deleteDocument as apiDeleteDocument,
  duplicateDocument as apiDuplicateDocument,
  getBacklinks as apiGetBacklinks,
  getDocument as apiGetDocument,
  getDocumentContent as apiGetDocumentContent,
  getDocumentSnapshotDiff as apiGetDocumentSnapshotDiff,
  getOutgoingLinks as apiGetOutgoingLinks,
  listDocumentSnapshots as apiListDocumentSnapshots,
  listDocuments as apiListDocuments,
  restoreDocumentSnapshot as apiRestoreDocumentSnapshot,
  unarchiveDocument as apiUnarchiveDocument,
  updateDocument as apiUpdateDocument,
  updateDocumentContent as apiUpdateDocumentContent,
} from '@/shared/api'
import type {
  DocumentListResponse,
  Document as ApiDocument,
  BacklinksResponse,
  OutgoingLinksResponse,
  SnapshotListResponse,
  SnapshotDiffBaseParam,
  SnapshotDiffResponse,
  SnapshotRestoreResponse,
  SnapshotSummary,
} from '@/shared/api'


type DocumentListParams = {
  tag?: string
  state?: 'active' | 'archived' | 'all'
  workspaceId?: string | null
}

export const documentKeys = {
  all: ['documents'] as const,
  list: (params?: DocumentListParams) =>
    [
      'documents',
      'list',
      params?.workspaceId ?? 'current',
      params?.state ?? 'active',
      params?.tag ?? null,
    ] as const,
  byId: (id: string) => ['documents', id] as const,
  backlinks: (id: string) => ['documents', id, 'backlinks'] as const,
  links: (id: string) => ['documents', id, 'links'] as const,
  snapshots: (id: string) => ['documents', id, 'snapshots'] as const,
  snapshotDiff: (
    id: string,
    snapshotId: string,
    compare?: string | null,
    base?: SnapshotDiffBaseParam | 'auto'
  ) => ['documents', id, 'snapshot', snapshotId, compare ?? 'current', base ?? 'auto'] as const,
}

export const listDocumentsQuery = (params?: DocumentListParams) => {
  const state = params?.state ?? 'active'
  return {
    queryKey: documentKeys.list({ ...params, state }),
    queryFn: () =>
      apiListDocuments({
        tag: params?.tag ?? null,
        state,
      }) as Promise<DocumentListResponse>,
  }
}

export const backlinksQuery = (id: string) => ({
  queryKey: documentKeys.backlinks(id),
  queryFn: () => apiGetBacklinks({ id }) as Promise<BacklinksResponse>,
  enabled: !!id,
})

export const outgoingLinksQuery = (id: string) => ({
  queryKey: documentKeys.links(id),
  queryFn: () => apiGetOutgoingLinks({ id }) as Promise<OutgoingLinksResponse>,
  enabled: !!id,
})

export function useBacklinks(id: string) {
  return useQuery(backlinksQuery(id))
}

export function useOutgoingLinks(id: string) {
  return useQuery(outgoingLinksQuery(id))
}

export const documentSnapshotsQuery = (id: string, params?: { token?: string | null }) => ({
  queryKey: documentKeys.snapshots(id),
  queryFn: () =>
    apiListDocumentSnapshots({
      id,
      token: params?.token ?? null,
      limit: null,
      offset: null,
    }) as Promise<SnapshotListResponse>,
  enabled: !!id,
})

export function useDocumentSnapshots(id: string, params?: { token?: string | null }) {
  return useQuery(documentSnapshotsQuery(id, params))
}

export const snapshotDiffQuery = (
  id: string,
  snapshotId: string,
  params?: { compare?: string | null; base?: SnapshotDiffBaseParam | 'auto'; token?: string | null },
) => ({
  queryKey: documentKeys.snapshotDiff(
    id,
    snapshotId,
    params?.compare ?? undefined,
    params?.base ?? 'auto'
  ),
  queryFn: () =>
    apiGetDocumentSnapshotDiff({
      id,
      snapshotId,
      compare: params?.compare ?? null,
      base: params?.base === 'auto' ? null : params?.base ?? null,
      token: params?.token ?? null,
    }) as Promise<SnapshotDiffResponse>,
})

export async function triggerSnapshotRestore(params: {
  documentId: string
  snapshotId: string
  token?: string | null
}): Promise<SnapshotSummary> {
  const response = (await apiRestoreDocumentSnapshot({
    id: params.documentId,
    snapshotId: params.snapshotId,
    token: params.token ?? null,
  })) as SnapshotRestoreResponse
  return response.snapshot
}

// Note: Snapshot download is temporarily unavailable.
// Server-side export has been removed for E2EE compliance.
// Client-side snapshot export will be implemented in a future update.
export async function downloadSnapshot(_params: {
  documentId: string
  snapshotId: string
  token?: string | null
  filename?: string
}): Promise<string> {
  throw new Error('Snapshot download is not yet available. This feature is being migrated to client-side export for E2EE compliance.')
}

export function useCreateDocument() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { title?: string; parentId?: string | null; type?: 'folder' | 'document' }) =>
      apiCreateDocument({
        requestBody: {
          title: input.title ?? 'Untitled',
          parentId: input.parentId ?? null,
          type: input.type,
        },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: documentKeys.all })
    },
  })
}

export function useDuplicateDocument(options?: { onSuccess?: (document: ApiDocument) => void }) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { id: string; title?: string; parent_id?: string | null }) => {
      const body: Record<string, unknown> = {}
      if (input.title !== undefined) body.title = input.title
      if (Object.prototype.hasOwnProperty.call(input, 'parent_id')) {
        body.parent_id = input.parent_id ?? null
      }
      return apiDuplicateDocument({
        id: input.id,
        requestBody: (body as any) || {},
      }) as Promise<ApiDocument>
    },
    onSuccess: (doc) => {
      qc.invalidateQueries({ queryKey: documentKeys.all })
      options?.onSuccess?.(doc as ApiDocument)
    },
  })
}

export function useArchiveDocument(options?: { onSuccess?: (document: ApiDocument, id: string) => void }) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => apiArchiveDocument({ id }) as Promise<ApiDocument>,
    onSuccess: (doc, id) => {
      qc.invalidateQueries({ queryKey: documentKeys.all })
      options?.onSuccess?.(doc, id)
    },
  })
}

export function useUnarchiveDocument(options?: { onSuccess?: (document: ApiDocument, id: string) => void }) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => apiUnarchiveDocument({ id }) as Promise<ApiDocument>,
    onSuccess: (doc, id) => {
      qc.invalidateQueries({ queryKey: documentKeys.all })
      options?.onSuccess?.(doc, id)
    },
  })
}

export type Document = ApiDocument

// Use-case oriented helpers
export async function fetchDocumentMeta(id: string, token?: string) {
  return apiGetDocument({ id, token: token ?? undefined })
}

export async function fetchDocumentContent(id: string) {
  return apiGetDocumentContent({ id })
}

export async function listDocuments(params?: { tag?: string | null; state?: 'active' | 'archived' | 'all' }) {
  return apiListDocuments({
    tag: params?.tag ?? null,
    state: params?.state ?? 'active',
  })
}

export async function createDocument(input: { title?: string; parent_id?: string | null; type?: 'folder' | 'document' }) {
  return apiCreateDocument({ requestBody: input as any })
}

export async function duplicateDocument(params: { id: string; title?: string; parent_id?: string | null }) {
  const body: Record<string, unknown> = {}
  if (params.title !== undefined) body.title = params.title
  if (Object.prototype.hasOwnProperty.call(params, 'parent_id')) {
    body.parent_id = params.parent_id ?? null
  }
  return apiDuplicateDocument({
    id: params.id,
    requestBody: (body as any) || {},
  })
}

export async function updateDocumentTitle(id: string, title: string) {
  return apiUpdateDocument({ id, requestBody: { title } as any })
}

export async function updateDocumentParent(id: string, parent_id: string | null) {
  return apiUpdateDocument({ id, requestBody: { parent_id } as any })
}

export async function updateDocumentContent(params: { id: string; content: string; token?: string | null }) {
  return apiUpdateDocumentContent({
    id: params.id,
    token: params.token ?? null,
    requestBody: { content: params.content },
  })
}

export async function deleteDocument(id: string) {
  return apiDeleteDocument({ id })
}
