import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { BookmarkPlus, Download, History } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'

import { ApiError } from '@/shared/api'
import { useRealtime } from '@/shared/contexts/realtime-context'
import type { DocumentHeaderAction } from '@/shared/types/document'
import { Button } from '@/shared/ui/button'

import { downloadDocumentFile, type DocumentDownloadFormat } from '@/entities/document'
import { createShareMount, shareMountsQuery } from '@/entities/share'

import { useAuthContext } from '@/features/auth'
import {
  DocumentDownloadDialog,
  OTHER_DOWNLOAD_FORMAT_GROUPS,
  PRIMARY_DOWNLOAD_OPTIONS,
} from '@/features/document-download'
import { SnapshotHistoryDialog } from '@/features/document-snapshots'
import { EditorOverlay, MarkdownEditor, useCollaborativeDocument } from '@/features/edit-document'
import type { PreviewPaneProps } from '@/features/edit-document/ui/PreviewPane'
import { finalizeConflictResolution, resolveConflict, type ConflictResolution } from '@/features/git-sync'
import { setConflicts as setGlobalConflicts, readConflicts, clearAllConflicts, type ConflictItem } from '@/features/git-sync/lib/git-conflict-store'
import { PluginDocumentMount } from '@/features/plugins/ui/PluginDocumentMount'
import { UnlockPrompt } from '@/features/security'

export type DocumentLoaderData = {
  title: string
  token?: string
  createdByPlugin?: string | null
  path?: string | null
  desired_path?: string | null
  workspace_id?: string | null
}

export type DocumentPageProps = {
  id: string
  loaderData?: DocumentLoaderData
  shareToken?: string
  conflictMode?: boolean
  render?: (ctx: DocumentPageRenderContext) => ReactNode
}

export type DocumentPageRenderContext = {
  id: string
  loaderData?: DocumentLoaderData
  shareToken?: string
  conflictMode: boolean
  status: ReturnType<typeof useCollaborativeDocument>['status']
  doc: ReturnType<typeof useCollaborativeDocument>['doc']
  awareness: ReturnType<typeof useCollaborativeDocument>['awareness']
  isReadOnly: ReturnType<typeof useCollaborativeDocument>['isReadOnly']
  realtimeError: ReturnType<typeof useCollaborativeDocument>['error']
  overlayLabel: string
  showOverlay: boolean
  markdownEditorProps: Parameters<typeof MarkdownEditor>[0] | null
  previewOverride: string | undefined
  resolvedTitle: string
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
  conflicts: ConflictItem[],
  docPaths: Array<string | null | undefined>,
  docId: string,
): ConflictItem | null => {
  if (conflicts.length === 0) return null
  const targets = docPaths
    .map((p) => normalizeConflictPath(p))
    .filter((p) => p.length > 0)

  for (const conflict of conflicts) {
    if (conflict.documentId && conflict.documentId === docId) return conflict
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

export function DocumentPage({ id, loaderData, shareToken, conflictMode = false, render }: DocumentPageProps) {
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
      render={render}
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
  render,
  conflictMode = false,
}: DocumentPageProps) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { user, activeWorkspaceId } = useAuthContext()
  const { documentTitle: realtimeTitle, documentActions, setDocumentActions, documentPluginId } = useRealtime()
  const pluginIdHintFromLoader = typeof loaderData?.createdByPlugin === 'string' ? loaderData.createdByPlugin.trim() : ''
  const pluginIdHintFromRealtime = typeof documentPluginId === 'string' ? documentPluginId.trim() : ''
  const pluginIdHint = pluginIdHintFromLoader || pluginIdHintFromRealtime
  const [showSnapshots, setShowSnapshots] = useState(false)
  const openSnapshots = useCallback(() => setShowSnapshots(true), [])
  const [showDownloadDialog, setShowDownloadDialog] = useState(false)
  const [downloadPending, setDownloadPending] = useState(false)
  const [savingShare, setSavingShare] = useState(false)
  const [activeConflict, setActiveConflict] = useState<ConflictItem | null>(null)
  const [resolutionPending, setResolutionPending] = useState(false)
  const [modifiedText, setModifiedText] = useState<string>('')
  const [previewContent, setPreviewContent] = useState<string>('')
  const [hasInteracted, setHasInteracted] = useState(false)
  const [segments, setSegments] = useState<ConflictSegments>([])
  const [hunks, setHunks] = useState<ConflictHunk[]>([])
  const [hunkChoices, setHunkChoices] = useState<Record<string, 'ours' | 'theirs'>>({})
  const [hunkDefaultSide, setHunkDefaultSide] = useState<'ours' | 'theirs'>('ours')
  const [hunkAnchors, setHunkAnchors] = useState<Array<{ hunkId: string; line: number }>>([])
  const { status, doc, awareness, isReadOnly, error: realtimeError, needsKeyVaultUnlock, retryKeyVaultCheck } = useCollaborativeDocument(id, shareToken)
  const hasDoc = Boolean(doc)
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

  const setConflictsForDoc = useCallback(
    (list: ConflictItem[]) => {
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
    // Load conflicts from client-side store
    setConflictsForDoc(readConflicts())
  }, [conflictMode, setConflictsForDoc])

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
      const workspaceId = loaderData?.workspace_id ?? activeWorkspaceId
      if (!workspaceId) {
        toast.error('Workspace not available for export')
        return
      }
      setDownloadPending(true)
      try {
        const filename = await downloadDocumentFile(id, workspaceId, {
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
    [hasDoc, id, loaderData?.workspace_id, activeWorkspaceId, resolvedTitle],
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
    clearAllConflicts()
    qc.invalidateQueries({ queryKey: ['git-status'] })
  }, [id, navigate, qc, setConflictsForDoc])

  const submitResolution = useCallback(
    async (resolution: ConflictResolution) => {
      if (!activeConflict || !activeWorkspaceId) return

      setResolutionPending(true)
      try {
        // Resolve the conflict with the chosen content
        await resolveConflict(
          activeWorkspaceId,
          resolution,
          activeConflict.ours,
          activeConflict.theirs
        )

        // Finalize the resolution (creates merge commit and pushes)
        const result = await finalizeConflictResolution(activeWorkspaceId)

        if (result.success) {
          toast.success(result.message || 'Conflict resolved')
          handleConflictResolved()
        } else {
          toast.error(result.message || 'Failed to apply resolution')
        }
      } catch (error) {
        toast.error((error as Error)?.message || 'Failed to apply resolution')
      } finally {
        setResolutionPending(false)
      }
    },
    [activeConflict, activeWorkspaceId, handleConflictResolved],
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

    let next = ensureAction(actions, snapshotAction)
    next = ensureAction(next, downloadAction)
    if (shareToken) {
      next = ensureAction(next, saveShareAction)
    }
    if (next !== actions) {
      setDocumentActions(next)
    }
  }, [documentActions, setDocumentActions, openSnapshots, hasDoc, openDownloadDialog, handleSaveShare, shareToken, user, savingShare])

  const hasCollaborativeState = Boolean(doc && awareness)

  const shouldShowOverlay = Boolean(realtimeError) || !hasCollaborativeState

  const overlayLabel = realtimeError || (status === 'connecting' ? 'Connecting...' : 'Loading...')
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
    (choice: ConflictResolution['choice'], customContent?: string) => {
      if (!activeConflict) return
      if (choice === 'custom' && !allResolved) {
        toast.error('Resolve all hunks before applying.')
        return
      }
      if (choice === 'custom' && !(customContent ?? modifiedText).trim()) {
        toast.error('Add your merged content before applying.')
        return
      }
      const resolution: ConflictResolution = {
        path: activeConflict.path,
        choice,
        customContent: choice === 'custom' ? customContent ?? modifiedText : undefined,
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
        readOnly: resolutionPending,
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
                handleApplyResolution('custom', modifiedText)
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
              disabled={resolutionPending}
              onClick={() => applyGlobalChoice('ours')}
            >
              Keep mine
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="rounded-full px-3"
              disabled={resolutionPending}
              onClick={() => applyGlobalChoice('theirs')}
            >
              Take remote
            </Button>
            <Button
              size="sm"
              variant="default"
              className="rounded-full px-3"
              disabled={resolutionPending || !allResolved}
              onClick={() => handleApplyResolution('custom', modifiedText)}
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

  const usePluginPreview = Boolean(pluginIdHint) && !conflictMode
  const renderPluginPreview = useCallback(
    (_props: PreviewPaneProps) => (
      <PluginDocumentMount
        docId={id}
        token={shareToken}
        pluginIdHint={pluginIdHint}
        variant="preview"
        mode="primary"
        className="h-full w-full overflow-auto"
      />
    ),
    [id, pluginIdHint, shareToken],
  )

  const markdownEditorProps = hasEditorSession
    ? ({
        doc: doc!,
        awareness: awareness!,
        connected: status === 'connected',
        initialView: 'editor',
        userId: user?.id || anonIdentity?.id,
        userName: user?.name || anonIdentity?.name,
        documentId: id,
        workspaceId: loaderData?.workspace_id ?? activeWorkspaceId,
        readOnly: isReadOnly || Boolean(activeConflict),
        conflictView,
        conflictHunkWidgets,
        conflictBadgeText,
        conflictControls,
        previewOverride: previewOverrideValue,
        extraRight: undefined,
        renderPreview: usePluginPreview ? renderPluginPreview : undefined,
      } satisfies Parameters<typeof MarkdownEditor>[0])
    : null

  const renderContext: DocumentPageRenderContext = {
    id,
    loaderData,
    shareToken,
    conflictMode,
    status,
    doc,
    awareness,
    isReadOnly,
    realtimeError,
    overlayLabel,
    showOverlay,
    markdownEditorProps,
    previewOverride: previewOverrideValue,
    resolvedTitle: resolvedTitle || '',
  }

  // Handle E2EE unlock requirement
  const handleUnlocked = useCallback(() => {
    // Retry E2EE check to reinitialize the document connection with unlocked keys
    retryKeyVaultCheck()
  }, [retryKeyVaultCheck])

  // Show unlock prompt if E2EE is locked
  if (needsKeyVaultUnlock) {
    return (
      <div className="flex h-full items-center justify-center p-4">
        <UnlockPrompt onUnlocked={handleUnlocked} />
      </div>
    )
  }

  const body = render ? (
    render(renderContext)
  ) : (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      {showOverlay ? <EditorOverlay label={overlayLabel} /> : null}
      {showEditor && markdownEditorProps ? <MarkdownEditor key={id} {...markdownEditorProps} /> : null}
    </div>
  )

  return (
    <>
      {body}
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
