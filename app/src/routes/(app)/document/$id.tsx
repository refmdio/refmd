import { createFileRoute, useParams } from '@tanstack/react-router'

import { useIsMobile } from '@/shared/hooks/use-mobile'

import { fetchDocumentMeta } from '@/entities/document'
import { buildCanonicalUrl, buildOgImageUrl } from '@/entities/public'

import { documentBeforeLoadGuard } from '@/features/auth'
import { useAttachmentContext } from '@/features/e2ee'

import DocumentMosaicWorkspace from '@/widgets/document/DocumentMosaicWorkspace'
import DocumentPage, { type DocumentLoaderData } from '@/widgets/document/DocumentPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export type DocumentRouteSearch = {
  token?: string
  shareScope?: 'folder' | 'document'
  shareMount?: string
  share_mount?: string
  conflict?: string
  [key: string]: string | string[] | undefined
}

type LoaderData = DocumentLoaderData

function normalizeDocumentSearch(search: Record<string, unknown>): DocumentRouteSearch {
  const result: DocumentRouteSearch = {}
  for (const [key, value] of Object.entries(search)) {
    if (typeof value === 'string') {
      result[key] = value
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      result[key] = String(value)
    } else if (Array.isArray(value)) {
      const strings = value.filter((item): item is string => typeof item === 'string')
      if (strings.length) {
        result[key] = strings.length === 1 ? strings[0] : strings
      }
    }
  }
  return result
}

export const Route = createFileRoute('/(app)/document/$id')({
  staticData: { layout: 'document' },
  ssr: true,
  validateSearch: normalizeDocumentSearch,
  pendingComponent: () => <RoutePending label="Loading editor…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: documentBeforeLoadGuard,
  loader: async ({ params, location }) => {
    const normalizedSearch = normalizeDocumentSearch((location?.search ?? {}) as Record<string, unknown>)
    const token = typeof normalizedSearch.token === 'string' && normalizedSearch.token.trim().length > 0 ? normalizedSearch.token.trim() : undefined
    try {
      const meta = await fetchDocumentMeta(params.id, token)
      const title = typeof meta?.title === 'string' ? meta.title.trim() : ''
      const createdByPlugin = meta?.created_by_plugin ?? null
      const workspace_id = meta?.owner_id ?? null
      return { title, token, createdByPlugin, path: meta?.path ?? null, desired_path: meta?.desired_path ?? null, workspace_id } satisfies LoaderData
    } catch {
      return { title: '', token, createdByPlugin: undefined, path: null, desired_path: null, workspace_id: null } satisfies LoaderData
    }
  },
  head: ({ loaderData, params }) => {
    const data = (loaderData as LoaderData | undefined) ?? { title: '', token: undefined }
    const token = data.token
    const baseTitle = data.title?.trim() || 'Untitled Document'
    const isShare = Boolean(token)
    const metaTitle = isShare ? baseTitle : `${baseTitle} • RefMD`
    const description = isShare ? baseTitle : `${baseTitle} on RefMD`
    const query = token ? `?token=${encodeURIComponent(token)}` : ''
    const canonicalPath = `/document/${encodeURIComponent(params.id)}${query}`
    const { base, url: canonicalUrl } = buildCanonicalUrl(canonicalPath)
    const ogImage = buildOgImageUrl(base, {
      variant: 'document',
      title: baseTitle,
      subtitle: isShare ? 'Shared document on RefMD' : 'Workspace document',
      description,
      badge: isShare ? 'Shared Document' : 'Document',
      meta: isShare ? 'refmd.io - share link' : 'refmd.io',
    })

    return {
      meta: [
        { title: metaTitle },
        { name: 'description', content: description },
        { property: 'og:title', content: metaTitle },
        { property: 'og:description', content: description },
        { property: 'og:type', content: 'article' },
        { property: 'og:url', content: canonicalUrl },
        { property: 'og:image', content: ogImage },
        { name: 'twitter:card', content: 'summary_large_image' },
        { name: 'twitter:title', content: metaTitle },
        { name: 'twitter:description', content: description },
        { name: 'twitter:image', content: ogImage },
      ],
      links: [{ rel: 'canonical', href: canonicalUrl }],
    }
  },
  component: DocumentRouteComponent,
})

function DocumentRouteComponent() {
  const { id } = useParams({ from: '/(app)/document/$id' })
  const loaderData = Route.useLoaderData() as LoaderData | undefined
  const search = Route.useSearch() as DocumentRouteSearch
  const isMobile = useIsMobile()
  const shareToken = loaderData?.token ?? (typeof search.token === 'string' && search.token.trim().length > 0 ? search.token.trim() : undefined)
  const workspaceId = loaderData?.workspace_id ?? null

  // Initialize attachment context at page level (before any child components)
  // This ensures file map is ready when Markdown renders
  useAttachmentContext({
    documentId: id,
    workspaceId,
    token: shareToken,
    setAsDefault: true,
  })

  const shareScope = search.shareScope === 'folder' || search.shareScope === 'document' ? search.shareScope : undefined
  const isShareMount = (() => {
    const raw = search.shareMount ?? search.share_mount
    if (raw == null) return false
    if (typeof raw === 'string') {
      const normalized = raw.trim().toLowerCase()
      return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on'
    }
    return Boolean(raw)
  })()
  const conflictMode = Object.prototype.hasOwnProperty.call(search, 'conflict')
  if (isMobile) {
    return (
      <DocumentPage
        id={id}
        loaderData={loaderData}
        shareToken={shareToken}
        conflictMode={conflictMode}
      />
    )
  }
  return (
    <DocumentMosaicWorkspace
      id={id}
      loaderData={loaderData}
      shareToken={shareToken}
      shareScope={shareScope}
      isShareMount={isShareMount}
      conflictMode={conflictMode}
    />
  )
}
