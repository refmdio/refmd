import { createFileRoute, useNavigate, useParams } from '@tanstack/react-router'
import { useEffect, useMemo } from 'react'

import { documentBeforeLoadGuard, useAuthContext } from '@/features/auth'
import { BacklinksPanel } from '@/features/document-backlinks'
import { EditorOverlay, MarkdownEditor, useViewContext } from '@/features/edit-document'
import { usePluginDocumentRedirect } from '@/features/plugins'
import { useSecondaryViewer } from '@/features/secondary-viewer'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import SecondaryViewer from '@/widgets/secondary-viewer/SecondaryViewer'

import { useCollaborativeDocument, useRealtime } from '@/processes/collaboration'

export type DocumentRouteSearch = {
  token?: string
  [key: string]: string | string[] | undefined
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
  validateSearch: normalizeDocumentSearch,
  pendingComponent: () => <RoutePending label="Loading editor…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: documentBeforeLoadGuard,
  component: InnerDocument,
})

function InnerDocument() {
  const { id } = useParams({ from: '/(app)/document/$id' })
  const navigate = useNavigate()
  const { user } = useAuthContext()
  const { secondaryDocumentId, secondaryDocumentType, showSecondaryViewer, closeSecondaryViewer, openSecondaryViewer } = useSecondaryViewer()
  const { showBacklinks, setShowBacklinks } = useViewContext()
  const { status, doc, awareness, isReadOnly, error: realtimeError } = useCollaborativeDocument(id)
  const { documentTitle: realtimeTitle } = useRealtime()
  const redirecting = usePluginDocumentRedirect(id, {
    navigate: (to) => navigate({ to }),
  })
  // Prepare user identity for awareness (host shows proper name, anonymous gets distinct label)
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
  // loader state is derived inline in JSX
  useEffect(() => {
    setShowBacklinks(false)
  }, [id, setShowBacklinks])
  useEffect(() => {
    if (showBacklinks && showSecondaryViewer) {
      // hide secondary viewer when backlinks open (exclusive right pane)
      closeSecondaryViewer()
    }
  }, [showBacklinks, showSecondaryViewer, closeSecondaryViewer])
  // Backlinks are controlled via ViewContext; no window events
  const shouldShowOverlay =
    redirecting ||
    Boolean(realtimeError) ||
    status !== 'connected' ||
    !doc ||
    !awareness

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
    const computedTitle = realtimeTitle ? `${realtimeTitle} • RefMD` : 'RefMD'
    document.title = computedTitle

    const summary = realtimeTitle ? `${realtimeTitle} on RefMD` : 'Editing a document on RefMD'
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
  }, [id, realtimeTitle])

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
                onDocumentChange={(id, type) => openSecondaryViewer(id, type)}
                className="h-full"
              />
            ) : undefined)}
        />
      )}
    </div>
  )
}
