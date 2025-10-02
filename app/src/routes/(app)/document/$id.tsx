import { createFileRoute, useNavigate, useParams } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'

import { documentBeforeLoadGuard, useAuthContext } from '@/features/auth'
import { BacklinksPanel } from '@/features/document-backlinks'
import { EditorOverlay, MarkdownEditor, useViewContext } from '@/features/edit-document'
import { usePluginDocumentRedirect } from '@/features/plugins'
import { useSecondaryViewer } from '@/features/secondary-viewer'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import SecondaryViewer from '@/widgets/secondary-viewer/SecondaryViewer'

import { useCollaborativeDocument, useRealtime } from '@/processes/collaboration'
import { fetchDocumentMeta } from '@/entities/document'
import { buildCanonicalUrl, buildOgImageUrl } from '@/entities/public/lib/seo'

export type DocumentRouteSearch = {
  token?: string
  [key: string]: string | string[] | undefined
}

type LoaderData = {
  title: string
  token?: string
}

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
  loader: async ({ params, context }) => {
    const normalizedSearch = normalizeDocumentSearch(((context as any)?.search ?? {}) as Record<string, unknown>)
    const token = typeof normalizedSearch.token === 'string' && normalizedSearch.token.trim().length > 0 ? normalizedSearch.token.trim() : undefined
    try {
      const meta = await fetchDocumentMeta(params.id, token)
      const title = typeof meta?.title === 'string' ? meta.title.trim() : ''
      return { title, token } satisfies LoaderData
    } catch {
      return { title: '', token } satisfies LoaderData
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
    const ogImage = buildOgImageUrl(base)

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
  component: InnerDocument,
})

function InnerDocument() {
  const { id } = useParams({ from: '/(app)/document/$id' })
  const loaderData = Route.useLoaderData() as LoaderData | undefined
  const search = Route.useSearch() as DocumentRouteSearch
  const shareToken = loaderData?.token ?? (typeof search.token === 'string' && search.token.trim().length > 0 ? search.token.trim() : undefined)
  const [isClient, setIsClient] = useState(typeof window !== 'undefined')

  useEffect(() => {
    setIsClient(true)
  }, [])

  if (!isClient) {
    return <DocumentSSRPlaceholder />
  }

  return <DocumentClient id={id} loaderData={loaderData} shareToken={shareToken} />
}

function DocumentSSRPlaceholder() {
  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      <EditorOverlay label="Loading…" />
    </div>
  )
}

function DocumentClient({
  id,
  loaderData,
  shareToken,
}: {
  id: string
  loaderData?: LoaderData
  shareToken?: string
}) {
  const navigate = useNavigate()
  const { user } = useAuthContext()
  const { secondaryDocumentId, secondaryDocumentType, showSecondaryViewer, closeSecondaryViewer, openSecondaryViewer } = useSecondaryViewer()
  const { showBacklinks, setShowBacklinks } = useViewContext()
  const { status, doc, awareness, isReadOnly, error: realtimeError } = useCollaborativeDocument(id)
  const { documentTitle: realtimeTitle } = useRealtime()
  const redirecting = usePluginDocumentRedirect(id, {
    navigate: (to) => navigate({ to }),
  })
  const anonIdentity = useMemo(() => {
    if (user) return null
    try {
      const keyName = 'refmd_anon_identity'
      const saved = localStorage.getItem(keyName)
      if (saved) return JSON.parse(saved) as { id: string; name: string }
      const rnd = Math.random().toString(36).slice(-4)
      const ident = { id: `guest:${rnd}`, name: `Guest-${rnd}` }
      localStorage.setItem(keyName, JSON.stringify(ident))
      return ident
    } catch {
      const rnd = Math.random().toString(36).slice(-4)
      return { id: `guest:${rnd}`, name: `Guest-${rnd}` }
    }
  }, [user])

  useEffect(() => {
    setShowBacklinks(false)
  }, [id, setShowBacklinks])

  useEffect(() => {
    if (showBacklinks && showSecondaryViewer) {
      closeSecondaryViewer()
    }
  }, [showBacklinks, showSecondaryViewer, closeSecondaryViewer])

  const hasCollaborativeState = Boolean(doc && awareness)

  const shouldShowOverlay = redirecting || Boolean(realtimeError) || !hasCollaborativeState

  const overlayLabel = realtimeError
    ? realtimeError
    : redirecting
      ? 'Loading…'
      : status === 'connecting'
        ? 'Connecting…'
        : 'Loading…'

  useEffect(() => {
    if (typeof document === 'undefined') return
    const originalTitle = document.title
    const baseTitle = (realtimeTitle && realtimeTitle.trim()) || loaderData?.title?.trim() || ''
    const computedTitle = (() => {
      if (!baseTitle) return 'RefMD'
      if (shareToken) return baseTitle
      return `${baseTitle} • RefMD`
    })()
    document.title = computedTitle

    const summary = (() => {
      if (!baseTitle) return shareToken ? 'Shared document on RefMD' : 'Editing a document on RefMD'
      if (shareToken) return baseTitle
      return `${baseTitle} on RefMD`
    })()

    const metaDefs: Array<{ selector: string; attr: 'name' | 'property'; value: string }> = [
      { selector: 'description', attr: 'name', value: summary },
      { selector: 'og:title', attr: 'property', value: computedTitle },
      { selector: 'og:description', attr: 'property', value: summary },
      { selector: 'og:url', attr: 'property', value: typeof window !== 'undefined' ? window.location.href : '' },
      { selector: 'og:type', attr: 'property', value: 'article' },
    ]

    const cleanupFns: Array<() => void> = []
    for (const def of metaDefs) {
      if (!def.value) continue
      const selector = def.attr === 'name' ? `meta[name="${def.selector}"]` : `meta[property="${def.selector}"]`
      const element = document.head.querySelector(selector) as HTMLMetaElement | null
      if (element) {
        const prev = element.getAttribute('content')
        element.setAttribute('content', def.value)
        cleanupFns.push(() => {
          if (prev == null) element.removeAttribute('content')
          else element.setAttribute('content', prev)
        })
      } else {
        const metaEl = document.createElement('meta')
        metaEl.setAttribute(def.attr, def.selector)
        metaEl.setAttribute('content', def.value)
        document.head.appendChild(metaEl)
        cleanupFns.push(() => {
          document.head.removeChild(metaEl)
        })
      }
    }

    return () => {
      document.title = originalTitle
      cleanupFns.forEach((fn) => fn())
    }
  }, [id, realtimeTitle, loaderData?.title, shareToken])

  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      {shouldShowOverlay && <EditorOverlay label={overlayLabel} />}
      {doc && awareness && !realtimeError && (
        <MarkdownEditor
          key={id}
          doc={doc}
          awareness={awareness}
          connected={status === 'connected'}
          initialView="split"
          userId={user?.id || anonIdentity?.id}
          userName={user?.name || anonIdentity?.name}
          documentId={id}
          readOnly={isReadOnly}
          extraRight={showBacklinks ? (
            <BacklinksPanel documentId={id} className="h-full" onClose={() => setShowBacklinks(false)} />
          ) : (showSecondaryViewer && secondaryDocumentId ? (
              <SecondaryViewer
                documentId={secondaryDocumentId}
                documentType={secondaryDocumentType}
                onClose={closeSecondaryViewer}
                onDocumentChange={(docId, type) => openSecondaryViewer(docId, type)}
                className="h-full"
              />
            ) : undefined)}
        />
      )}
    </div>
  )
}
