import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { BookmarkPlus, Download, History } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'

import { ApiError } from '@/shared/api'
import { useRealtime } from '@/shared/contexts/realtime-context'
import type { DocumentHeaderAction } from '@/shared/types/document'

import { downloadDocumentFile, type DocumentDownloadFormat } from '@/entities/document'
import { createShareMount, shareMountsQuery } from '@/entities/share'

import { useAuthContext } from '@/features/auth'
import { BacklinksPanel } from '@/features/document-backlinks'
import {
  DocumentDownloadDialog,
  OTHER_DOWNLOAD_FORMAT_GROUPS,
  PRIMARY_DOWNLOAD_OPTIONS,
} from '@/features/document-download'
import { SnapshotHistoryDialog } from '@/features/document-snapshots'
import { EditorOverlay, MarkdownEditor, useCollaborativeDocument, useViewContext } from '@/features/edit-document'
import { usePluginDocumentRedirect } from '@/features/plugins'
import { useSecondaryViewer } from '@/features/secondary-viewer'


type SecondaryViewerType = ReturnType<typeof useSecondaryViewer>['secondaryDocumentType']

export type DocumentLoaderData = {
  title: string
  token?: string
}

export type SecondaryViewerRendererProps = {
  documentId: string
  documentType?: SecondaryViewerType
  onClose: () => void
  onDocumentChange: (id: string, type?: SecondaryViewerType) => void
  className?: string
}

export type DocumentPageProps = {
  id: string
  loaderData?: DocumentLoaderData
  shareToken?: string
  secondaryViewerRenderer?: (props: SecondaryViewerRendererProps) => ReactNode
}

export function DocumentPage({ id, loaderData, shareToken, secondaryViewerRenderer }: DocumentPageProps) {
  const [isClient, setIsClient] = useState(typeof window !== 'undefined')

  useEffect(() => {
    setIsClient(true)
  }, [])

  if (!isClient) {
    return <DocumentSSRPlaceholder />
  }

  return (
    <DocumentClient
      id={id}
      loaderData={loaderData}
      shareToken={shareToken}
      secondaryViewerRenderer={secondaryViewerRenderer}
    />
  )
}

export default DocumentPage

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
  secondaryViewerRenderer,
}: DocumentPageProps) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { user } = useAuthContext()
  const [showSnapshots, setShowSnapshots] = useState(false)
  const openSnapshots = useCallback(() => setShowSnapshots(true), [])
  const [showDownloadDialog, setShowDownloadDialog] = useState(false)
  const [downloadPending, setDownloadPending] = useState(false)
  const [savingShare, setSavingShare] = useState(false)
  const { secondaryDocumentId, secondaryDocumentType, showSecondaryViewer, closeSecondaryViewer, openSecondaryViewer } = useSecondaryViewer()
  const { showBacklinks, setShowBacklinks } = useViewContext()
  const { status, doc, awareness, isReadOnly, error: realtimeError } = useCollaborativeDocument(id, shareToken)
  const { documentTitle: realtimeTitle, documentActions, setDocumentActions } = useRealtime()
  const hasDoc = Boolean(doc)
  const { redirecting } = usePluginDocumentRedirect(id, {
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

  const loaderTitle = loaderData?.title
  const resolvedTitle = (realtimeTitle && realtimeTitle.trim()) || loaderTitle

  const openDownloadDialog = useCallback(() => {
    if (!hasDoc) return
    setShowDownloadDialog(true)
  }, [hasDoc])

  const handleDownload = useCallback(
    async (format: DocumentDownloadFormat) => {
      if (!hasDoc) return
      setDownloadPending(true)
      try {
        const filename = await downloadDocumentFile(id, {
          token: shareToken,
          title: resolvedTitle,
          format,
        })
        toast.success(`Download ready: ${filename}`)
        setShowDownloadDialog(false)
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to download document'
        toast.error(message)
      } finally {
        setDownloadPending(false)
      }
    },
    [hasDoc, id, shareToken, resolvedTitle],
  )

  const handleSaveShare = useCallback(async () => {
    if (!shareToken) return
    if (savingShare) return
    setSavingShare(true)
    try {
      await createShareMount({ token: shareToken })
      qc.invalidateQueries({ queryKey: shareMountsQuery().queryKey })
      toast.success('Saved to your workspace')
    } catch (error) {
      const status = error instanceof ApiError ? error.status : (error as any)?.status ?? (error as any)?.cause?.status
      if (status === 401 || status === 403) {
        toast.error('Could not save (auth required or expired). Reload and try again.')
      } else {
        const message = error instanceof Error ? error.message : 'Failed to save share'
        toast.error(message)
      }
    } finally {
      setSavingShare(false)
    }
  }, [qc, savingShare, shareToken])

  useEffect(() => {
    const ensureAction = (
      list: DocumentHeaderAction[],
      action: DocumentHeaderAction,
    ): DocumentHeaderAction[] => {
      const existing = list.find((item) => item.id === action.id)
      if (!existing) {
        return [...list, action]
      }
      if (
        existing.onSelect !== action.onSelect ||
        existing.disabled !== action.disabled ||
        existing.label !== action.label
      ) {
        return list.map((item) => (item.id === action.id ? action : item))
      }
      return list
    }

    const actions = documentActions ?? []
    const snapshotAction: DocumentHeaderAction = {
      id: 'snapshot-history',
      label: 'Snapshots',
      onSelect: openSnapshots,
      disabled: !hasDoc,
      icon: <History className="h-4 w-4" />,
      tooltip: 'Snapshot history',
    }
    const downloadAction: DocumentHeaderAction = {
      id: 'download-document',
      label: 'Download',
      onSelect: openDownloadDialog,
      disabled: !hasDoc,
      icon: <Download className="h-4 w-4" />,
      tooltip: 'Download document',
    }
    const saveShareAction: DocumentHeaderAction = {
      id: 'save-share',
      label: 'Save to workspace',
      onSelect: handleSaveShare,
      disabled: !shareToken || !user || savingShare,
      icon: <BookmarkPlus className="h-4 w-4" />,
      tooltip: 'Add this shared document to your workspace file tree',
    }

    let next = ensureAction(actions, snapshotAction)
    next = ensureAction(next, downloadAction)
    if (shareToken) {
      next = ensureAction(next, saveShareAction)
    }
    if (next !== actions) {
      setDocumentActions(next)
    }
  }, [documentActions, setDocumentActions, openSnapshots, hasDoc, openDownloadDialog, handleSaveShare, shareToken, user, savingShare])

  useEffect(() => {
    if (showBacklinks && showSecondaryViewer) {
      closeSecondaryViewer()
    }
  }, [showBacklinks, showSecondaryViewer, closeSecondaryViewer])

  const hasCollaborativeState = Boolean(doc && awareness)

  const shouldShowOverlay = redirecting || Boolean(realtimeError) || !hasCollaborativeState

  const overlayLabel = realtimeError
    ? realtimeError
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

  const renderSecondaryViewer = secondaryViewerRenderer

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
          readOnly={isReadOnly || redirecting}
          extraRight={
            showBacklinks ? (
              <BacklinksPanel documentId={id} className="h-full" onClose={() => setShowBacklinks(false)} />
            ) : showSecondaryViewer && secondaryDocumentId && renderSecondaryViewer ? (
              renderSecondaryViewer({
                documentId: secondaryDocumentId,
                documentType: secondaryDocumentType,
                onClose: closeSecondaryViewer,
                onDocumentChange: (docId, type) => openSecondaryViewer(docId, type),
                className: 'h-full',
              })
            ) : undefined
          }
        />
      )}
      <SnapshotHistoryDialog
        documentId={id}
        open={showSnapshots}
        onOpenChange={setShowSnapshots}
        token={shareToken}
        canRestore={!isReadOnly}
      />
      <DocumentDownloadDialog
        open={showDownloadDialog}
        onOpenChange={setShowDownloadDialog}
        primaryOptions={PRIMARY_DOWNLOAD_OPTIONS}
        otherGroups={OTHER_DOWNLOAD_FORMAT_GROUPS}
        onSelect={handleDownload}
        isPending={downloadPending}
      />
    </div>
  )
}
