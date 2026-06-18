import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { BookmarkPlus, Download, History, MessageSquare } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'

import { ApiError, type GitPullConflictItem, type GitPullResolution } from '@/shared/api'
import { useRealtime } from '@/shared/contexts/realtime-context'
import {
  OPEN_DOCUMENT_PLUGIN_PANE_EVENT,
  dispatchOpenDocumentPluginPane,
} from '@/shared/lib/document-workspace-events'
import type { DocumentHeaderAction } from '@/shared/types/document'
import { Button } from '@/shared/ui/button'

import { downloadDocumentFile, type DocumentDownloadFormat } from '@/entities/document'
import { getPullSession } from '@/entities/git'
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
import { setConflicts as setGlobalConflicts, readResolutions, setResolutions, clearResolutions, readSessionId, setSessionId, clearSession, readConflicts, subscribeSessionId } from '@/features/git-sync/lib/git-conflict-store'
import { performPullSession } from '@/features/git-sync/lib/pull-session-manager'
import { usePluginDocumentRedirect } from '@/features/plugins'
import { renderDocumentPaneIcon } from '@/features/plugins/lib/pane-icons'
import type { DocumentEditorPaneHostState } from '@/features/plugins/model/useDocumentEditorPlugins'
import { useSecondaryViewer } from '@/features/secondary-viewer'

import SecondaryViewer from '@/widgets/secondary-viewer/SecondaryViewer'

export type DocumentLoaderData = {
  title: string
  token?: string
  createdByPlugin?: string | null
  path?: string | null
  desired_path?: string | null
}

export type DocumentPageProps = {
  id: string
  loaderData?: DocumentLoaderData
  shareToken?: string
  conflictMode?: boolean
}

const normalizeConflictPath = (path?: string | null) => (path || '').replace(/^[./]+/, '').trim().toLowerCase()

type ConflictHunk = {
  id: string
  ours: string[]
  theirs: string[]
  oursStart?: number
  theirsStart?: number
}

type ConflictSegments = Array<
  | { type: 'equal'; lines: string[] }
  | { type: 'conflict'; hunkId: string; ours: string[]; theirs: string[] }
>

const genHunkId = () => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID()
  return Math.random().toString(36).slice(2)
}

const documentPluginPaneActionPrefix = 'document-plugin-pane:'

const buildLineDiffSegments = (oursRaw: string, theirsRaw: string): { segments: ConflictSegments; hunks: ConflictHunk[] } => {
  const ours = oursRaw.split('\n')
  const theirs = theirsRaw.split('\n')
  const m = ours.length
  const n = theirs.length
  const lcs: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0))
  for (let i = m - 1; i >= 0; i -= 1) {
    for (let j = n - 1; j >= 0; j -= 1) {
      if (ours[i] === theirs[j]) lcs[i][j] = lcs[i + 1][j + 1] + 1
      else lcs[i][j] = Math.max(lcs[i + 1][j], lcs[i][j + 1])
    }
  }

  type Op = { type: 'equal' | 'del' | 'ins'; line: string }
  const ops: Op[] = []
  let i = 0
  let j = 0
  while (i < m && j < n) {
    if (ours[i] === theirs[j]) {
      ops.push({ type: 'equal', line: ours[i] })
      i += 1
      j += 1
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push({ type: 'del', line: ours[i] })
      i += 1
    } else {
      ops.push({ type: 'ins', line: theirs[j] })
      j += 1
    }
  }
  while (i < m) {
    ops.push({ type: 'del', line: ours[i] })
    i += 1
  }
  while (j < n) {
    ops.push({ type: 'ins', line: theirs[j] })
    j += 1
  }

  const segments: ConflictSegments = []
  const hunks: ConflictHunk[] = []
  let currentEqual: string[] = []
  let currentConflict: { ours: string[]; theirs: string[]; hunkId: string } | null = null

  const pushEqual = () => {
    if (currentEqual.length) {
      segments.push({ type: 'equal', lines: currentEqual })
      currentEqual = []
    }
  }

  const pushConflict = () => {
    if (currentConflict) {
      segments.push({ type: 'conflict', hunkId: currentConflict.hunkId, ours: currentConflict.ours, theirs: currentConflict.theirs })
      hunks.push({ id: currentConflict.hunkId, ours: currentConflict.ours.slice(), theirs: currentConflict.theirs.slice() })
      currentConflict = null
    }
  }

  for (const op of ops) {
    if (op.type === 'equal') {
      pushConflict()
      currentEqual.push(op.line)
    } else {
      pushEqual()
      if (!currentConflict) {
        currentConflict = { ours: [], theirs: [], hunkId: genHunkId() }
      }
      if (op.type === 'del') currentConflict.ours.push(op.line)
      else currentConflict.theirs.push(op.line)
    }
  }
  pushConflict()
  pushEqual()

  return { segments, hunks }
}

const buildMergedText = (
  segments: ConflictSegments,
  choices: Record<string, 'ours' | 'theirs'>,
  defaultPick: 'ours' | 'theirs' = 'ours',
) => {
  const out: string[] = []
  for (const seg of segments) {
    if (seg.type === 'equal') {
      out.push(...seg.lines)
    } else {
      const pick = choices[seg.hunkId] || defaultPick
      out.push(...(pick === 'theirs' ? seg.theirs : seg.ours))
    }
  }
  return out.join('\n')
}

const buildHunkAnchors = (
  segments: ConflictSegments,
  choices: Record<string, 'ours' | 'theirs'>,
  defaultPick: 'ours' | 'theirs',
): Array<{ hunkId: string; line: number }> => {
  const anchors: Array<{ hunkId: string; line: number }> = []
  let line = 0
  for (const seg of segments) {
    if (seg.type === 'equal') {
      line += seg.lines.length
    } else {
      const pick = choices[seg.hunkId] || defaultPick
      const lines = pick === 'theirs' ? seg.theirs : seg.ours
      const start = line + 1
      const end = line + lines.length
      anchors.push({ hunkId: seg.hunkId, line: lines.length ? end : start })
      line = end
    }
  }
  return anchors
}

const matchConflictToDoc = (
  conflicts: GitPullConflictItem[],
  docPaths: Array<string | null | undefined>,
  docId: string,
): GitPullConflictItem | null => {
  if (conflicts.length === 0) return null
  const targets = docPaths
    .map((p) => normalizeConflictPath(p))
    .filter((p) => p.length > 0)

  for (const conflict of conflicts) {
    if (conflict.document_id && conflict.document_id === docId) return conflict
  }

  for (const conflict of conflicts) {
    const candidate = normalizeConflictPath(conflict.path)
    if (!candidate) continue
    if (targets.some((t) => candidate === t || candidate.endsWith(`/${t}`))) {
      return conflict
    }
  }

  if (conflicts.length === 1) return conflicts[0]
  return null
}

export function DocumentPage({ id, loaderData, shareToken, conflictMode = false }: DocumentPageProps) {
  // This component intentionally renders a placeholder on the server.
  // Start from the same placeholder on the client to avoid hydration mismatches,
  // then switch to the interactive client UI after mount.
  const [isClient, setIsClient] = useState(false)

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
      conflictMode={conflictMode}
    />
  )
}

export default DocumentPage

function DocumentSSRPlaceholder() {
  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      <EditorOverlay label="Loading..." />
    </div>
  )
}

function DocumentClient({
  id,
  loaderData,
  shareToken,
  conflictMode = false,
}: DocumentPageProps) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { user } = useAuthContext()
  const { documentTitle: realtimeTitle, documentActions, setDocumentActions } = useRealtime()
  const { showBacklinks, setShowBacklinks } = useViewContext()
  const {
    secondaryDocumentId,
    secondaryDocumentType,
    showSecondaryViewer,
    closeSecondaryViewer,
    openSecondaryViewer,
  } = useSecondaryViewer()
  const pluginRedirectEnabled =
    loaderData?.createdByPlugin === undefined ? true : Boolean(loaderData?.createdByPlugin)
  const { redirecting, resolving: pluginResolving } = usePluginDocumentRedirect(id, {
    enabled: pluginRedirectEnabled,
    navigate: useCallback((to: string) => navigate({ to }), [navigate]),
  })
  const [showSnapshots, setShowSnapshots] = useState(false)
  const openSnapshots = useCallback(() => setShowSnapshots(true), [])
  const [showDownloadDialog, setShowDownloadDialog] = useState(false)
  const [downloadPending, setDownloadPending] = useState(false)
  const [savingShare, setSavingShare] = useState(false)
  const [showComments, setShowComments] = useState(false)
  const [activeConflict, setActiveConflict] = useState<GitPullConflictItem | null>(null)
  const [modifiedText, setModifiedText] = useState<string>('')
  const [previewContent, setPreviewContent] = useState<string>('')
  const [hasInteracted, setHasInteracted] = useState(false)
  const [segments, setSegments] = useState<ConflictSegments>([])
  const [hunks, setHunks] = useState<ConflictHunk[]>([])
  const [hunkChoices, setHunkChoices] = useState<Record<string, 'ours' | 'theirs'>>({})
  const [hunkDefaultSide, setHunkDefaultSide] = useState<'ours' | 'theirs'>('ours')
  const [hunkAnchors, setHunkAnchors] = useState<Array<{ hunkId: string; line: number }>>([])
  const documentPaneHostRef = useRef<DocumentEditorPaneHostState | null>(null)
  const [documentPanes, setDocumentPanes] = useState<DocumentEditorPaneHostState['panes']>([])
  const lastPayloadRef = useRef<GitPullResolution[]>([])
  const { status, doc, awareness, isReadOnly, error: realtimeError } = useCollaborativeDocument(id, shareToken)
  const hasDoc = Boolean(doc)
  const [sessionId, setSessionIdState] = useState<string | null>(() => readSessionId())
  useEffect(() => {
    const unsubscribe = subscribeSessionId((sid) => setSessionIdState(sid))
    return () => unsubscribe()
  }, [])

  const handleDocumentPaneHostChange = useCallback((host: DocumentEditorPaneHostState | null) => {
    documentPaneHostRef.current = host
    const nextPanes = host?.panes ?? []
    setDocumentPanes((current) => {
      if (
        current.length === nextPanes.length &&
        current.every((pane, index) => {
          const next = nextPanes[index]
          return (
            next &&
            pane.key === next.key &&
            pane.title === next.title &&
            pane.icon === next.icon &&
            pane.badge === next.badge
          )
        })
      ) {
        return current
      }
      return nextPanes
    })
  }, [])

  useEffect(() => {
    const panes = documentPanes
    const paneKeys = new Set(panes.map((pane) => `${documentPluginPaneActionPrefix}${id}:${pane.key}`))
    const currentActions = documentActions ?? []
    let next = currentActions.filter((action) => {
      if (!action.id?.startsWith(documentPluginPaneActionPrefix)) return true
      return paneKeys.has(action.id)
    })

    for (const pane of panes) {
      const actionId = `${documentPluginPaneActionPrefix}${id}:${pane.key}`
      const action = {
        id: actionId,
        label: pane.title,
        icon: renderDocumentPaneIcon(pane.icon),
        tooltip: `Open ${pane.title}`,
        onSelect: () => {
          dispatchOpenDocumentPluginPane(id, pane.key)
        },
      }
      const existing = next.find((item) => item.id === actionId)
      if (!existing) {
        next = [...next, action]
        continue
      }
      if (existing.label !== action.label || existing.tooltip !== action.tooltip) {
        next = next.map((item) => (item.id === actionId ? action : item))
      }
    }

    if (
      next.length !== currentActions.length ||
      next.some((action, index) => action !== currentActions[index])
    ) {
      setDocumentActions(next)
    }
  }, [documentActions, documentPanes, id, setDocumentActions])

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ documentId?: string; paneKey?: string }>).detail
      const documentId = typeof detail?.documentId === 'string' ? detail.documentId.trim() : ''
      if (documentId !== id) return
      const host = documentPaneHostRef.current
      if (!host || !host.panes.length) return
      const requested = typeof detail?.paneKey === 'string' ? detail.paneKey : ''
      const pane = host.panes.find((item) => item.key === requested) ?? host.panes[0]
      if (!pane) return
      setShowComments(false)
      setShowBacklinks(false)
      closeSecondaryViewer()
      host.openPane(pane.key)
    }
    window.addEventListener(OPEN_DOCUMENT_PLUGIN_PANE_EVENT, handler as EventListener)
    return () => window.removeEventListener(OPEN_DOCUMENT_PLUGIN_PANE_EVENT, handler as EventListener)
  }, [closeSecondaryViewer, id, setShowBacklinks])

  useEffect(() => {
    setShowBacklinks(false)
    setShowComments(false)
  }, [id, setShowBacklinks])

  useEffect(() => {
    if (showBacklinks && showSecondaryViewer) {
      closeSecondaryViewer()
    }
    if (showBacklinks || showSecondaryViewer) {
      setShowComments(false)
    }
  }, [closeSecondaryViewer, showBacklinks, showSecondaryViewer])
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

  const loaderTitle = loaderData?.title
  const resolvedTitle = (realtimeTitle && realtimeTitle.trim()) || loaderTitle

  const hasEditorSession = Boolean(doc && awareness)

  const toggleComments = useCallback(() => {
    setShowComments((current) => {
      const next = !current
      if (next) {
        setShowBacklinks(false)
        closeSecondaryViewer()
      }
      return next
    })
  }, [closeSecondaryViewer, setShowBacklinks])

  const setConflictsForDoc = useCallback(
    (list: GitPullConflictItem[]) => {
      const safeList = Array.isArray(list) ? list : []
      const existing = readConflicts()
      const unchanged =
        existing.length === safeList.length &&
        existing.every((item, idx) => JSON.stringify(item) === JSON.stringify(safeList[idx]))
      if (!unchanged) {
        setGlobalConflicts(safeList)
      }
      const matched = matchConflictToDoc(safeList, [loaderData?.path, loaderData?.desired_path], id)
      setActiveConflict(matched)
      if (matched && !matched.is_binary) {
        const oursText = matched.ours ?? ''
        const theirsText = matched.theirs ?? ''
        const { segments: segs, hunks: nextHunks } = buildLineDiffSegments(oursText, theirsText)
        setSegments(segs)
        setHunks(nextHunks)
        setHunkChoices({})
        setHunkDefaultSide('ours')
        // Default merge is ours, but show diff against remote by setting modified to theirs initially.
        setModifiedText(theirsText || oursText)
        setHunkAnchors(buildHunkAnchors(segs, {}, 'ours'))
        setPreviewContent(oursText)
        setHasInteracted(false)
      } else {
        setSegments([])
        setHunks([])
        setHunkChoices({})
        setHunkDefaultSide('ours')
        setModifiedText(matched?.theirs ?? matched?.ours ?? '')
        setHunkAnchors([])
        setPreviewContent('')
        setHasInteracted(false)
      }
    },
    [loaderData?.desired_path, loaderData?.path],
  )

  useEffect(() => {
    if (!conflictMode) return
    const fetchConflicts = async () => {
      try {
        if (sessionId) {
          const session = await getPullSession({ id: sessionId })
          if ((session as any)?.status === 'stale') {
            clearSession()
            clearResolutions()
            lastPayloadRef.current = []
            setConflictsForDoc([])
            toast.error('Pull session expired. Please pull again.')
            return
          }
          setSessionId(session.session_id)
          setConflictsForDoc(session.conflicts ?? [])
          setResolutions(session.resolutions ?? [])
          return
        }
        // Fallback: hydrate from local store when session is not yet available.
        setConflictsForDoc(readConflicts())
      } catch (error) {
        toast.error((error as any)?.body?.message || (error as any)?.message || 'Failed to load conflicts')
      }
    }
    void fetchConflicts()
  }, [conflictMode, setConflictsForDoc, sessionId])

  useEffect(() => {
    if (!segments.length) return
    if (hasInteracted) {
      setModifiedText(buildMergedText(segments, hunkChoices, hunkDefaultSide))
    }
    setHunkAnchors(buildHunkAnchors(segments, hunkChoices, hunkDefaultSide))
    setPreviewContent(buildMergedText(segments, hunkChoices, hunkDefaultSide))
  }, [segments, hunkChoices, hunkDefaultSide, hasInteracted])

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

  const handleConflictResolved = useCallback(() => {
    navigate({
      to: '/document/$id',
      params: { id },
      search: (prev: Record<string, string | string[] | undefined>) => {
        const next: Record<string, string | string[] | undefined> = { ...prev }
        delete next.conflict
        return next
      },
      replace: true,
    })
    setConflictsForDoc([])
    clearResolutions()
    clearSession()
    lastPayloadRef.current = []
    qc.invalidateQueries({ queryKey: ['git-status'] })
  }, [id, navigate, qc])

  const pullMutation = useMutation({
    mutationFn: async (resolutions: GitPullResolution[]) =>
      performPullSession(resolutions, { sessionId }),
    onSuccess: (result) => {
      setSessionIdState(result.sessionId ?? null)
      setConflictsForDoc(result.conflicts)

      if (result.status === 'stale') {
        clearSession()
        clearResolutions()
        lastPayloadRef.current = []
        toast.error('Pull session expired. Please pull again.')
        return
      }

      const stillPending = matchConflictToDoc(result.conflicts, [loaderData?.path, loaderData?.desired_path], id)
      if (result.status === 'conflicts') {
        const payload = lastPayloadRef.current || []
        if (payload.length) setResolutions(payload)
        const message =
          result.message ||
          (stillPending
            ? 'Resolution applied. Another conflict remains for this document.'
            : 'Resolution applied. Another conflict remains.')
        toast.success(message)
        return
      }

      if (result.status === 'merged') {
        clearResolutions()
        lastPayloadRef.current = []
        handleConflictResolved()
        toast.success(result.message || 'Conflict resolved')
        return
      }

      toast.error(result.message || 'Failed to apply resolution')
    },
  })

  const submitResolution = useCallback(
    (resolution: GitPullResolution) => {
      const preserved = readResolutions().filter((r) => r.path !== resolution.path)
      const payload = [...preserved, resolution]
      setResolutions(payload)
      lastPayloadRef.current = payload
      pullMutation.mutate(payload)
    },
    [pullMutation],
  )

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
    const commentsAction: DocumentHeaderAction = {
      id: 'document-comments',
      label: 'Comments',
      onSelect: toggleComments,
      disabled: !hasDoc || Boolean(activeConflict),
      icon: <MessageSquare className="h-4 w-4" />,
      tooltip: 'Comments',
    }

    let next = ensureAction(actions, snapshotAction)
    next = ensureAction(next, downloadAction)
    next = ensureAction(next, commentsAction)
    if (shareToken) {
      next = ensureAction(next, saveShareAction)
    }
    if (next !== actions) {
      setDocumentActions(next)
    }
  }, [activeConflict, documentActions, setDocumentActions, openSnapshots, hasDoc, openDownloadDialog, handleSaveShare, shareToken, user, savingShare, toggleComments])

  const hasCollaborativeState = Boolean(doc && awareness)

  const shouldShowOverlay = pluginResolving || redirecting || Boolean(realtimeError) || !hasCollaborativeState

  const overlayLabel = realtimeError
    ? realtimeError
    : pluginResolving
      ? 'Preparing plugin...'
      : redirecting
        ? 'Opening plugin...'
        : status === 'connecting'
          ? 'Connecting...'
          : 'Loading...'
  const showEditor = Boolean(doc && awareness && !realtimeError)
  const showOverlay = shouldShowOverlay

  useEffect(() => {
    if (typeof document === 'undefined') return
    const originalTitle = document.title
    const baseTitle = (realtimeTitle && realtimeTitle.trim()) || loaderData?.title?.trim() || ''
    const computedTitle = (() => {
      if (!baseTitle) return 'RefMD'
      if (shareToken) return baseTitle
      return `${baseTitle} - RefMD`
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

  const oursText = activeConflict?.ours ?? ''
  const theirsText = activeConflict?.theirs ?? ''
  const isBinaryConflict = activeConflict?.is_binary ?? false

  const hunkCount = useMemo(() => hunks.length, [hunks])
  const resolvedHunks = useMemo(() => hunks.filter((h) => hunkChoices[h.id]).length, [hunks, hunkChoices])
  const allResolved = useMemo(() => (hunkCount ? resolvedHunks === hunkCount : true), [hunkCount, resolvedHunks])

  const chooseHunkSide = useCallback((hunkId: string, side: 'ours' | 'theirs') => {
    setHunkChoices((prev) => ({ ...prev, [hunkId]: side }))
  }, [])

  const setAllHunks = useCallback(
    (side: 'ours' | 'theirs') => {
      if (!hunks.length) return
      const entries = Object.fromEntries(hunks.map((h) => [h.id, side]))
      setHunkChoices(entries)
      setHunkDefaultSide(side)
    },
    [hunks],
  )

  const applyGlobalChoice = useCallback(
    (side: 'ours' | 'theirs') => {
      setAllHunks(side)
      const nextText = side === 'theirs' ? theirsText : oursText
      setModifiedText(nextText)
      setPreviewContent(nextText)
    },
    [oursText, setAllHunks, setModifiedText, setPreviewContent, theirsText],
  )

  const handleApplyResolution = useCallback(
    (choice: GitPullResolution['choice'], customContent?: string) => {
      if (!activeConflict) return
      if (choice === 'custom_text' && !allResolved) {
        toast.error('Resolve all hunks before applying.')
        return
      }
      if (choice === 'custom_text' && !(customContent ?? modifiedText).trim()) {
        toast.error('Add your merged content before applying.')
        return
      }
      const resolution: GitPullResolution = {
        path: activeConflict.path,
        choice,
        content: choice === 'custom_text' ? customContent ?? modifiedText : undefined,
      }
      submitResolution(resolution)
    },
    [activeConflict, allResolved, modifiedText, submitResolution],
  )

  const showConflictUI = Boolean(activeConflict)

  const conflictView = showConflictUI && activeConflict
    ? {
        kind: isBinaryConflict ? 'binary' as const : 'text' as const,
        original: oursText,
        modified: modifiedText,
        onChange: (val: string) => {
          setHasInteracted(true)
          setModifiedText(val)
          setPreviewContent(val)
        },
        readOnly: pullMutation.isPending,
        actions: !isBinaryConflict
          ? {
              onKeepMine: () => {
                setHasInteracted(true)
                setAllHunks('ours')
                setModifiedText(oursText)
                setPreviewContent(oursText)
              },
              onTakeTheirs: () => {
                setHasInteracted(true)
                setAllHunks('theirs')
                setModifiedText(theirsText)
                setPreviewContent(theirsText)
              },
              onApplyMerged: () => {
                handleApplyResolution('custom_text', modifiedText)
              },
            }
          : undefined,
      }
    : undefined

  const conflictControls = showConflictUI
    ? (
      <div className="flex w-full flex-wrap items-center justify-end gap-2 sm:gap-3">
        {!isBinaryConflict ? (
          <>
            <Button
              size="sm"
              variant="outline"
              className="rounded-full px-3"
              disabled={pullMutation.isPending}
              onClick={() => applyGlobalChoice('ours')}
            >
              Keep mine
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="rounded-full px-3"
              disabled={pullMutation.isPending}
              onClick={() => applyGlobalChoice('theirs')}
            >
              Take remote
            </Button>
            <Button
              size="sm"
              variant="default"
              className="rounded-full px-3"
              disabled={pullMutation.isPending || !allResolved}
              onClick={() => handleApplyResolution('custom_text', modifiedText)}
            >
              Apply merge
            </Button>
          </>
        ) : null}
      </div>
    )
    : null

  const conflictBadgeText = !isBinaryConflict ? `${resolvedHunks}/${hunkCount} decided` : undefined

  const conflictHunkWidgets =
    showConflictUI && activeConflict && !isBinaryConflict && hunks.length
      ? hunkAnchors.map((anchor) => ({
          id: anchor.hunkId,
          line: anchor.line,
          choice: hunkChoices[anchor.hunkId],
          onChoose: (side: 'ours' | 'theirs') => chooseHunkSide(anchor.hunkId, side),
        }))
      : undefined

  const previewOverrideValue = showConflictUI && !isBinaryConflict ? previewContent || oursText : undefined

  const extraRight = showBacklinks ? (
    <BacklinksPanel documentId={id} className="h-full" onClose={() => setShowBacklinks(false)} />
  ) : showSecondaryViewer && secondaryDocumentId ? (
    <SecondaryViewer
      documentId={secondaryDocumentId}
      documentType={secondaryDocumentType}
      onClose={closeSecondaryViewer}
      onDocumentChange={(docId, type) => openSecondaryViewer(docId, type)}
      className="h-full"
    />
  ) : undefined

  const markdownEditorProps = hasEditorSession
    ? ({
        doc: doc!,
        awareness: awareness!,
        connected: status === 'connected',
        initialView: 'split',
        userId: user?.id || anonIdentity?.id,
        userName: user?.name || anonIdentity?.name,
        documentId: id,
        documentTitle: resolvedTitle || loaderData?.title || null,
        documentType: 'markdown',
        readOnly: isReadOnly || redirecting || Boolean(activeConflict),
        conflictView,
        conflictHunkWidgets,
        conflictBadgeText,
        conflictControls,
        previewOverride: previewOverrideValue,
        onDocumentEditorPaneHostChange: handleDocumentPaneHostChange,
        commentsOpen: showComments && !showBacklinks && !showSecondaryViewer,
        onCommentsOpenChange: setShowComments,
        extraRight,
      } satisfies Parameters<typeof MarkdownEditor>[0])
    : null

  return (
    <>
      <div className="relative flex h-full flex-1 min-h-0 flex-col">
        {showOverlay ? <EditorOverlay label={overlayLabel} /> : null}
        {showEditor && markdownEditorProps ? <MarkdownEditor key={id} {...markdownEditorProps} /> : null}
      </div>
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
    </>
  )
}
