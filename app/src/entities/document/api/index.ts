import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  archiveDocument as apiArchiveDocument,
  createDocumentCommentReply as apiCreateDocumentCommentReply,
  createDocumentCommentThread as apiCreateDocumentCommentThread,
  createDocument as apiCreateDocument,
  deleteDocument as apiDeleteDocument,
  downloadDocument as apiDownloadDocument,
  downloadDocumentSnapshot as apiDownloadDocumentSnapshot,
  downloadWorkspaceArchive as apiDownloadWorkspaceArchive,
  duplicateDocument as apiDuplicateDocument,
  getBacklinks as apiGetBacklinks,
  getDocument as apiGetDocument,
  getDocumentContent as apiGetDocumentContent,
  getDocumentSnapshotDiff as apiGetDocumentSnapshotDiff,
  getOutgoingLinks as apiGetOutgoingLinks,
  listDocumentComments as apiListDocumentComments,
  listDocumentSnapshots as apiListDocumentSnapshots,
  listDocuments as apiListDocuments,
  restoreDocumentSnapshot as apiRestoreDocumentSnapshot,
  unarchiveDocument as apiUnarchiveDocument,
  updateDocumentCommentThread as apiUpdateDocumentCommentThread,
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
  DownloadFormat,
  DocumentCommentReply as ApiDocumentCommentReply,
  DocumentCommentThread as ApiDocumentCommentThread,
  DocumentCommentsResponse as ApiDocumentCommentsResponse,
} from '@/shared/api'
import { ApiError } from '@/shared/api/client/core/ApiError'

type DocumentListParams = {
  query?: string
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
      params?.query ?? null,
      params?.tag ?? null,
    ] as const,
  byId: (id: string) => ['documents', id] as const,
  backlinks: (id: string) => ['documents', id, 'backlinks'] as const,
  links: (id: string) => ['documents', id, 'links'] as const,
  snapshots: (id: string) => ['documents', id, 'snapshots'] as const,
  comments: (id: string, token?: string | null) =>
    ['documents', id, 'comments', token ?? null] as const,
  snapshotDiff: (
    id: string,
    snapshotId: string,
    compare?: string | null,
    base?: SnapshotDiffBaseParam | 'auto',
  ) =>
    [
      'documents',
      id,
      'snapshot',
      snapshotId,
      compare ?? 'current',
      base ?? 'auto',
    ] as const,
}

export type DocumentCommentReply = {
  id: string
  threadId: string
  documentId: string
  body: string
  authorId: string | null
  authorName: string | null
  createdAt: string
}

export type DocumentCommentThread = {
  id: string
  documentId: string
  marker: string
  quote: string
  startLineNumber: number | null
  endLineNumber: number | null
  startOffset: number | null
  endOffset: number | null
  createdBy: string | null
  createdByName: string | null
  createdAt: string
  updatedAt: string
  resolvedAt: string | null
  resolvedBy: string | null
  replies: DocumentCommentReply[]
}

export type DocumentCommentsResponse = {
  threads: DocumentCommentThread[]
}

export type CreateDocumentCommentThreadInput = {
  documentId: string
  token?: string | null
  id: string
  marker: string
  quote: string
  body: string
  startLineNumber?: number | null
  endLineNumber?: number | null
  startOffset?: number | null
  endOffset?: number | null
  authorName?: string | null
}

export type CreateDocumentCommentReplyInput = {
  documentId: string
  threadId: string
  token?: string | null
  body: string
  authorName?: string | null
}

export type UpdateDocumentCommentThreadInput = {
  documentId: string
  threadId: string
  token?: string | null
  resolved: boolean
}

function toDocumentCommentReply(
  reply: ApiDocumentCommentReply,
): DocumentCommentReply {
  return {
    id: reply.id,
    threadId: reply.thread_id,
    documentId: reply.document_id,
    body: reply.body,
    authorId: reply.created_by ?? null,
    authorName: reply.created_by_name ?? null,
    createdAt: reply.created_at,
  }
}

function toDocumentCommentThread(
  thread: ApiDocumentCommentThread,
): DocumentCommentThread {
  return {
    id: thread.id,
    documentId: thread.document_id,
    marker: thread.marker,
    quote: thread.quote,
    startLineNumber: thread.start_line_number ?? null,
    endLineNumber: thread.end_line_number ?? null,
    startOffset: thread.start_offset ?? null,
    endOffset: thread.end_offset ?? null,
    createdBy: thread.created_by ?? null,
    createdByName: thread.created_by_name ?? null,
    createdAt: thread.created_at,
    updatedAt: thread.updated_at,
    resolvedAt: thread.resolved_at ?? null,
    resolvedBy: thread.resolved_by ?? null,
    replies: thread.replies.map(toDocumentCommentReply),
  }
}

export async function listDocumentComments(
  documentId: string,
  token?: string | null,
): Promise<DocumentCommentsResponse> {
  const response = (await apiListDocumentComments({
    id: documentId,
    token: token ?? null,
  })) as ApiDocumentCommentsResponse
  return { threads: response.threads.map(toDocumentCommentThread) }
}

export async function createDocumentCommentThread(
  input: CreateDocumentCommentThreadInput,
): Promise<DocumentCommentThread> {
  const response = (await apiCreateDocumentCommentThread({
    id: input.documentId,
    token: input.token ?? null,
    requestBody: {
      id: input.id,
      marker: input.marker,
      quote: input.quote,
      body: input.body,
      start_line_number: input.startLineNumber ?? null,
      end_line_number: input.endLineNumber ?? null,
      start_offset: input.startOffset ?? null,
      end_offset: input.endOffset ?? null,
      author_name: input.authorName ?? null,
    },
  })) as ApiDocumentCommentThread
  return toDocumentCommentThread(response)
}

export async function createDocumentCommentReply(
  input: CreateDocumentCommentReplyInput,
): Promise<DocumentCommentReply> {
  const response = (await apiCreateDocumentCommentReply({
    id: input.documentId,
    threadId: input.threadId,
    token: input.token ?? null,
    requestBody: {
      body: input.body,
      author_name: input.authorName ?? null,
    },
  })) as ApiDocumentCommentReply
  return toDocumentCommentReply(response)
}

export async function updateDocumentCommentThread(
  input: UpdateDocumentCommentThreadInput,
): Promise<DocumentCommentThread> {
  const response = (await apiUpdateDocumentCommentThread({
    id: input.documentId,
    threadId: input.threadId,
    token: input.token ?? null,
    requestBody: { resolved: input.resolved },
  })) as ApiDocumentCommentThread
  return toDocumentCommentThread(response)
}

export const documentCommentsQuery = (
  id: string,
  params?: { token?: string | null },
) => ({
  queryKey: documentKeys.comments(id, params?.token),
  queryFn: () => listDocumentComments(id, params?.token),
  enabled: !!id,
})

export const listDocumentsQuery = (params?: DocumentListParams) => {
  const state = params?.state ?? 'active'
  return {
    queryKey: documentKeys.list({ ...params, state }),
    queryFn: () =>
      apiListDocuments({
        query: params?.query ?? null,
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

export const documentSnapshotsQuery = (
  id: string,
  params?: { token?: string | null },
) => ({
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

export function useDocumentSnapshots(
  id: string,
  params?: { token?: string | null },
) {
  return useQuery(documentSnapshotsQuery(id, params))
}

export const snapshotDiffQuery = (
  id: string,
  snapshotId: string,
  params?: {
    compare?: string | null
    base?: SnapshotDiffBaseParam | 'auto'
    token?: string | null
  },
) => ({
  queryKey: documentKeys.snapshotDiff(
    id,
    snapshotId,
    params?.compare ?? undefined,
    params?.base ?? 'auto',
  ),
  queryFn: () =>
    apiGetDocumentSnapshotDiff({
      id,
      snapshotId,
      compare: params?.compare ?? null,
      base: params?.base === 'auto' ? null : (params?.base ?? null),
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

export async function downloadSnapshot(params: {
  documentId: string
  snapshotId: string
  token?: string | null
  filename?: string
}) {
  const blob = (await apiDownloadDocumentSnapshot({
    id: params.documentId,
    snapshotId: params.snapshotId,
    token: params.token ?? null,
  })) as Blob
  const name = params.filename ?? `snapshot-${params.snapshotId}.zip`
  const url = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = name
    link.style.display = 'none'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  } finally {
    URL.revokeObjectURL(url)
  }
  return name
}

export function useCreateDocument() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      title?: string
      parent_id?: string | null
      type?: 'folder' | 'document'
    }) =>
      apiCreateDocument({
        requestBody: {
          title: input.title ?? 'Untitled',
          parent_id: input.parent_id ?? null,
          type: input.type,
        },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: documentKeys.all })
    },
  })
}

export function useDuplicateDocument(options?: {
  onSuccess?: (document: ApiDocument) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      id: string
      title?: string
      parent_id?: string | null
    }) => {
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

export function useArchiveDocument(options?: {
  onSuccess?: (document: ApiDocument, id: string) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) =>
      apiArchiveDocument({ id }) as Promise<ApiDocument>,
    onSuccess: (doc, id) => {
      qc.invalidateQueries({ queryKey: documentKeys.all })
      options?.onSuccess?.(doc, id)
    },
  })
}

export function useUnarchiveDocument(options?: {
  onSuccess?: (document: ApiDocument, id: string) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) =>
      apiUnarchiveDocument({ id }) as Promise<ApiDocument>,
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

export async function listDocuments(params?: {
  query?: string | null
  tag?: string | null
  state?: 'active' | 'archived' | 'all'
}) {
  return apiListDocuments({
    query: params?.query ?? null,
    tag: params?.tag ?? null,
    state: params?.state ?? 'active',
  })
}

export async function createDocument(input: {
  title?: string
  parent_id?: string | null
  type?: 'folder' | 'document'
}) {
  return apiCreateDocument({ requestBody: input as any })
}

export async function duplicateDocument(params: {
  id: string
  title?: string
  parent_id?: string | null
}) {
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

export async function updateDocumentParent(
  id: string,
  parent_id: string | null,
) {
  return apiUpdateDocument({ id, requestBody: { parent_id } as any })
}

export async function updateDocumentContent(params: {
  id: string
  content: string
  token?: string | null
}) {
  return apiUpdateDocumentContent({
    id: params.id,
    token: params.token ?? null,
    requestBody: { content: params.content },
  })
}

export async function deleteDocument(id: string) {
  return apiDeleteDocument({ id })
}

export type DocumentDownloadFormat = DownloadFormat

export type DocumentDownloadFormatCategory = 'primary' | 'other'

export type DocumentDownloadFormatMetadata = {
  label: string
  description: string
  extension: string
  category: DocumentDownloadFormatCategory
  group?: string
}

export const DOWNLOAD_FORMAT_METADATA: Record<
  DocumentDownloadFormat,
  DocumentDownloadFormatMetadata
> = {
  archive: {
    label: 'ZIP archive',
    description: 'Markdown with all attachments bundled',
    extension: 'zip',
    category: 'primary',
  },
  markdown: {
    label: 'Markdown (.md)',
    description: 'Plain markdown document only',
    extension: 'md',
    category: 'primary',
  },
  html: {
    label: 'HTML (.html)',
    description: 'Self-contained HTML page',
    extension: 'html',
    category: 'primary',
  },
  html5: {
    label: 'HTML5 (.html)',
    description: 'HTML5 output; self-contained page',
    extension: 'html',
    category: 'other',
    group: 'Web & Slides',
  },
  pdf: {
    label: 'PDF (.pdf)',
    description: 'Portable Document Format export',
    extension: 'pdf',
    category: 'primary',
  },
  docx: {
    label: 'Word (.docx)',
    description: 'Microsoft Word compatible document',
    extension: 'docx',
    category: 'primary',
  },
  latex: {
    label: 'LaTeX (.tex)',
    description: 'LaTeX document source',
    extension: 'tex',
    category: 'other',
    group: 'TeX & Academic',
  },
  beamer: {
    label: 'Beamer slides (.tex)',
    description: 'LaTeX Beamer slide deck',
    extension: 'tex',
    category: 'other',
    group: 'TeX & Academic',
  },
  context: {
    label: 'ConTeXt (.tex)',
    description: 'ConTeXt document source',
    extension: 'tex',
    category: 'other',
    group: 'TeX & Academic',
  },
  man: {
    label: 'Man page (.man)',
    description: 'Groff man page source',
    extension: 'man',
    category: 'other',
    group: 'Manuals',
  },
  mediawiki: {
    label: 'MediaWiki (.mediawiki)',
    description: 'MediaWiki markup',
    extension: 'mediawiki',
    category: 'other',
    group: 'Wiki & Markup',
  },
  dokuwiki: {
    label: 'DokuWiki (.txt)',
    description: 'DokuWiki markup',
    extension: 'txt',
    category: 'other',
    group: 'Wiki & Markup',
  },
  textile: {
    label: 'Textile (.textile)',
    description: 'Textile markup',
    extension: 'textile',
    category: 'other',
    group: 'Wiki & Markup',
  },
  org: {
    label: 'Org-mode (.org)',
    description: 'Emacs Org-mode document',
    extension: 'org',
    category: 'other',
    group: 'Wiki & Markup',
  },
  texinfo: {
    label: 'Texinfo (.texi)',
    description: 'GNU Texinfo document',
    extension: 'texi',
    category: 'other',
    group: 'Wiki & Markup',
  },
  opml: {
    label: 'OPML (.opml)',
    description: 'Outline Processor Markup Language document',
    extension: 'opml',
    category: 'other',
    group: 'Data & Interchange',
  },
  docbook: {
    label: 'DocBook XML (.xml)',
    description: 'DocBook XML document',
    extension: 'xml',
    category: 'other',
    group: 'Data & Interchange',
  },
  opendocument: {
    label: 'OpenDocument Flat XML (.fodt)',
    description: 'Flat OpenDocument Text document',
    extension: 'fodt',
    category: 'other',
    group: 'Office & Rich Text',
  },
  odt: {
    label: 'ODT (.odt)',
    description: 'OpenDocument Text document',
    extension: 'odt',
    category: 'other',
    group: 'Office & Rich Text',
  },
  rtf: {
    label: 'RTF (.rtf)',
    description: 'Rich Text Format document',
    extension: 'rtf',
    category: 'other',
    group: 'Office & Rich Text',
  },
  epub: {
    label: 'EPUB 2 (.epub)',
    description: 'EPUB eBook (v2)',
    extension: 'epub',
    category: 'other',
    group: 'E-books',
  },
  epub3: {
    label: 'EPUB 3 (.epub)',
    description: 'EPUB eBook (v3)',
    extension: 'epub',
    category: 'other',
    group: 'E-books',
  },
  fb2: {
    label: 'FictionBook (.fb2)',
    description: 'FictionBook eBook',
    extension: 'fb2',
    category: 'other',
    group: 'E-books',
  },
  asciidoc: {
    label: 'AsciiDoc (.adoc)',
    description: 'AsciiDoc markup',
    extension: 'adoc',
    category: 'other',
    group: 'Wiki & Markup',
  },
  icml: {
    label: 'ICML (.icml)',
    description: 'Adobe InCopy ICML document',
    extension: 'icml',
    category: 'other',
    group: 'Office & Rich Text',
  },
  slidy: {
    label: 'Slidy (.html)',
    description: 'Slidy HTML presentation',
    extension: 'html',
    category: 'other',
    group: 'Web & Slides',
  },
  slideous: {
    label: 'Slideous (.html)',
    description: 'Slideous HTML presentation',
    extension: 'html',
    category: 'other',
    group: 'Web & Slides',
  },
  dzslides: {
    label: 'DZSlides (.html)',
    description: 'DZSlides HTML presentation',
    extension: 'html',
    category: 'other',
    group: 'Web & Slides',
  },
  revealjs: {
    label: 'reveal.js (.html)',
    description: 'reveal.js HTML presentation',
    extension: 'html',
    category: 'other',
    group: 'Web & Slides',
  },
  s5: {
    label: 'S5 (.html)',
    description: 'S5 HTML presentation',
    extension: 'html',
    category: 'other',
    group: 'Web & Slides',
  },
  json: {
    label: 'Pandoc JSON (.json)',
    description: 'Pandoc JSON abstract syntax tree',
    extension: 'json',
    category: 'other',
    group: 'Data & Interchange',
  },
  plain: {
    label: 'Plain text (.txt)',
    description: 'Plain UTF-8 text output',
    extension: 'txt',
    category: 'other',
    group: 'Wiki & Markup',
  },
  commonmark: {
    label: 'CommonMark (.md)',
    description: 'CommonMark markdown',
    extension: 'md',
    category: 'other',
    group: 'Wiki & Markup',
  },
  commonmark_x: {
    label: 'CommonMark+Extensions (.md)',
    description: 'CommonMark with extensions',
    extension: 'md',
    category: 'other',
    group: 'Wiki & Markup',
  },
  markdown_strict: {
    label: 'Markdown (strict) (.md)',
    description: 'Original markdown syntax',
    extension: 'md',
    category: 'other',
    group: 'Wiki & Markup',
  },
  markdown_phpextra: {
    label: 'Markdown (PHP Extra) (.md)',
    description: 'Markdown PHP Extra dialect',
    extension: 'md',
    category: 'other',
    group: 'Wiki & Markup',
  },
  markdown_github: {
    label: 'GitHub Markdown (.md)',
    description: 'GitHub-flavoured markdown',
    extension: 'md',
    category: 'other',
    group: 'Wiki & Markup',
  },
  rst: {
    label: 'reStructuredText (.rst)',
    description: 'reStructuredText document',
    extension: 'rst',
    category: 'other',
    group: 'Wiki & Markup',
  },
  native: {
    label: 'Pandoc native (.hs)',
    description: 'Pandoc native Haskell AST',
    extension: 'hs',
    category: 'other',
    group: 'Data & Interchange',
  },
  haddock: {
    label: 'Haddock (.txt)',
    description: 'Haddock markup (Haskell docs)',
    extension: 'txt',
    category: 'other',
    group: 'Wiki & Markup',
  },
} as const

export async function downloadDocumentFile(
  id: string,
  options?: { token?: string; title?: string; format?: DocumentDownloadFormat },
) {
  const format: DocumentDownloadFormat = options?.format ?? 'archive'
  let payload: unknown
  try {
    payload = await apiDownloadDocument({
      id,
      token: options?.token ?? null,
      format,
    })
  } catch (error) {
    if (error instanceof ApiError) {
      const body = error.body as { message?: unknown } | undefined
      if (body && typeof body === 'object' && 'message' in body) {
        const messageValue = (body as { message?: unknown }).message
        if (typeof messageValue === 'string') {
          throw new Error(messageValue)
        }
      }
    }
    throw error
  }
  const mimeType = resolveMimeType(format)
  const blob =
    payload instanceof Blob
      ? payload
      : typeof payload === 'string'
        ? new Blob([payload], { type: mimeType })
        : payload && typeof payload === 'object'
          ? new Blob([JSON.stringify(payload, null, 2)], {
              type: 'application/json; charset=utf-8',
            })
          : undefined
  if (!(blob instanceof Blob)) {
    throw new Error('Unexpected download payload')
  }
  const extension = resolveExtension(format)
  const filename = `${sanitizeExportName(options?.title)}.${extension}`
  const blobUrl = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = blobUrl
    link.download = filename
    link.style.display = 'none'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  } finally {
    URL.revokeObjectURL(blobUrl)
  }
  return filename
}

export async function downloadWorkspaceArchive(params: {
  workspaceId: string
  workspaceName: string
  format?: DocumentDownloadFormat
}) {
  const format: DocumentDownloadFormat = params.format ?? 'archive'
  let payload: unknown
  try {
    payload = await apiDownloadWorkspaceArchive({
      id: params.workspaceId,
      format,
    })
  } catch (error) {
    if (error instanceof ApiError) {
      const body = error.body as { message?: unknown } | undefined
      if (body && typeof body === 'object' && 'message' in body) {
        const messageValue = (body as { message?: unknown }).message
        if (typeof messageValue === 'string') {
          throw new Error(messageValue)
        }
      }
    }
    throw error
  }
  const mimeType = resolveMimeType(format)
  const blob =
    payload instanceof Blob
      ? payload
      : typeof payload === 'string'
        ? new Blob([payload], { type: mimeType })
        : payload && typeof payload === 'object'
          ? new Blob([JSON.stringify(payload, null, 2)], {
              type: 'application/json; charset=utf-8',
            })
          : undefined
  if (!(blob instanceof Blob)) {
    throw new Error('Unexpected download payload')
  }
  const extension = resolveExtension(format)
  const filename = `${sanitizeExportName(params.workspaceName)}.${extension}`
  const blobUrl = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = blobUrl
    link.download = filename
    link.style.display = 'none'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  } finally {
    URL.revokeObjectURL(blobUrl)
  }
  return filename
}

function resolveExtension(format: DocumentDownloadFormat): string {
  return DOWNLOAD_FORMAT_METADATA[format]?.extension ?? format
}

function resolveMimeType(format: DocumentDownloadFormat): string {
  const extension = resolveExtension(format).toLowerCase()
  switch (extension) {
    case 'json':
      return 'application/json; charset=utf-8'
    case 'xml':
    case 'opml':
    case 'fb2':
      return 'application/xml; charset=utf-8'
    case 'fodt':
      return 'application/vnd.oasis.opendocument.text'
    case 'html':
      return 'text/html; charset=utf-8'
    case 'md':
      return 'text/markdown; charset=utf-8'
    case 'tex':
      return 'application/x-tex; charset=utf-8'
    default:
      return 'text/plain; charset=utf-8'
  }
}

function sanitizeExportName(input?: string) {
  const invalid = new Set(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'])
  let base = (input ?? '').trim()
  if (!base) base = 'document'
  let sanitized = ''
  for (const ch of base) {
    sanitized += invalid.has(ch) ? '-' : ch
  }
  sanitized = sanitized.replace(/ /g, '_')
  if (sanitized.length > 100) sanitized = sanitized.slice(0, 100)
  if (!sanitized) sanitized = 'document'
  return sanitized
}
