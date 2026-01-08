import { EditorView } from '@codemirror/view'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import type { Awareness } from 'y-protocols/awareness'
import * as Y from 'yjs'

import { useShareToken } from '@/shared/contexts/share-token-context'
import { useTheme } from '@/shared/contexts/theme-context'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { useShortcut } from '@/shared/hooks/use-shortcut'
import { MOSAIC_SCROLL_SYNC_EVENT, type MosaicScrollSyncDetail, dispatchMosaicScrollSync } from '@/shared/lib/mosaic-events'
import type { ViewMode } from '@/shared/types/view-mode'

import { listDocuments } from '@/entities/document'

import { useEditorBinding } from '@/features/edit-document/hooks/useEditorBinding'
import { useEditorUploads } from '@/features/edit-document/hooks/useEditorUploads'
import { useMarkdownCommands, type MarkdownCommand } from '@/features/edit-document/hooks/useMarkdownCommands'
import { useScrollSync } from '@/features/edit-document/hooks/useScrollSync'
import { awarenessExtension, awarenessStyles } from '@/features/edit-document/lib/editor/awareness'
import { enableVimMode, disableVimMode } from '@/features/edit-document/lib/editor/vim'
import { useEditorContext } from '@/features/edit-document/model/editor-context'
import { useViewContext } from '@/features/edit-document/model/view-context'

import CursorDisplay from './CursorDisplay'
import EditorLayout from './EditorLayout'
import type { PreviewPaneProps } from './PreviewPane'
import EditorToolbar from './Toolbar'

const logEditorError = (scope: string, error: unknown) => {
  if (error instanceof Error) {
    console.error(`[editor] ${scope}:`, error)
  } else {
    console.error(`[editor] ${scope}:`, error)
  }
}

const safeExecute = (scope: string, fn: () => void) => {
  try {
    fn()
  } catch (error) {
    logEditorError(scope, error)
  }
}

export type MarkdownEditorProps = {
  doc: Y.Doc
  awareness: Awareness
  connected: boolean
  initialView?: ViewMode
  forcedView?: ViewMode
  embedded?: boolean
  scrollSyncGroupId?: string | null
  userName?: string
  userId?: string
  documentId: string
  readOnly?: boolean
  extraRight?: React.ReactNode
  conflictControls?: React.ReactNode
  conflictHunkWidgets?: Array<{
    id: string
    line: number
    choice?: 'ours' | 'theirs'
    onChoose: (side: 'ours' | 'theirs') => void
  }>
  conflictBadgeText?: string
  conflictView?: {
    kind: 'text' | 'binary'
    original?: string
    modified?: string
    onChange?: (value: string) => void
    readOnly?: boolean
    actions?: {
      onKeepMine?: () => void
      onTakeTheirs?: () => void
      onApplyMerged?: () => void
    }
    theme?: string
  }
  previewOverride?: string
  renderPreview?: (props: PreviewPaneProps) => React.ReactNode
}

export function MarkdownEditor(props: MarkdownEditorProps) {
  const {
    doc,
    awareness,
    initialView: initialViewProp = 'editor',
    forcedView,
    embedded = false,
    scrollSyncGroupId = null,
    userId,
    userName,
    documentId,
    readOnly = false,
    extraRight,
    conflictControls,
    conflictHunkWidgets,
    conflictBadgeText,
    conflictView,
    previewOverride,
    renderPreview,
  } = props

  const { isDarkMode } = useTheme()
  const isMobile = useIsMobile()
  const { editor: activeEditor, setEditor, registerEditor } = useEditorContext()
  const { viewMode, setViewMode, viewModeHydrated, hasPersistentViewMode } = useViewContext()
  const navigate = useNavigate()
  const shareToken = useShareToken()

  const shareScope = useRouterState({
    select: (state) => {
      const raw = (state.location?.search as any)?.shareScope
      const scope = typeof raw === 'string' ? raw : null
      return scope === 'folder' || scope === 'document' ? scope : null
    },
  })

  const isShareMount = useRouterState({
    select: (state) => {
      const search = (state.location?.search ?? {}) as Record<string, unknown>
      const raw = (search as any)?.shareMount ?? (search as any)?.share_mount
      if (raw == null) return false
      if (typeof raw === 'string') {
        const normalized = raw.trim().toLowerCase()
        return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on'
      }
      if (typeof raw === 'number') return raw === 1
      return Boolean(raw)
    },
  })

  const isShareLink = Boolean(shareToken && !isShareMount)
  const view = forcedView ?? viewMode

  const [isVimMode, setIsVimMode] = useState<boolean>(() => typeof window !== 'undefined' && localStorage.getItem('editorVimMode') === 'true')
  const [syncScroll, setSyncScroll] = useState<boolean>(true)
  const [toolbarOpen, setToolbarOpen] = useState(false)

  const readOnlyWarningRef = useRef(0)
  const emitReadOnlyWarning = useCallback(() => {
    if (!readOnly) return
    const now = Date.now()
    if (now - readOnlyWarningRef.current < 1500) return
    readOnlyWarningRef.current = now
    toast.info('Document is read-only')
  }, [readOnly])

  const syncScrollRef = useRef<boolean>(true)
  useEffect(() => {
    syncScrollRef.current = syncScroll
  }, [syncScroll])

  const vimStatusBarRef = useRef<HTMLDivElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const viewRef = useRef<ViewMode>(forcedView ?? initialViewProp)
  const unregisterEditorRef = useRef<null | (() => void)>(null)

  useEffect(() => {
    viewRef.current = view as ViewMode
  }, [view])

  const mosaicGroupIdRef = useRef<string | null>(scrollSyncGroupId)
  useEffect(() => {
    mosaicGroupIdRef.current = scrollSyncGroupId
  }, [scrollSyncGroupId])

  const mosaicScrollRafRef = useRef<number | null>(null)
  const suppressMosaicEmitRef = useRef(false)
  const suppressMosaicTimeoutRef = useRef<number | null>(null)

  // Set up awareness user info
  useEffect(() => {
    if (!awareness || (awareness as any)?._destroyed) return

    const generateUserColor = (id?: string, light = false): string => {
      let hash = 0
      const str = id || Math.random().toString()
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i)
        hash = ((hash << 5) - hash) + char
        hash = hash & hash
      }
      const hue = Math.abs(hash) % 360
      const saturation = light ? 30 : 70
      const lightness = light ? 80 : 50
      return `hsl(${hue}, ${saturation}%, ${lightness}%)`
    }

    const info = {
      name: userName || `User-${awareness.clientID}`,
      color: generateUserColor(userId),
      colorLight: generateUserColor(userId, true),
      id: userId || String(awareness.clientID),
    }
    awareness.setLocalStateField('user', info)
  }, [awareness, userId, userName])

  // Editor binding hook
  const { text: boundText, editorRef, bindingExtensions, setEditorView } = useEditorBinding({
    doc,
    awareness,
    onTextChange: () => {},
  })

  // Create awareness extensions
  const awarenessExts = useMemo(() => {
    return [awarenessExtension(awareness), awarenessStyles()]
  }, [awareness])

  // Combined extensions
  const editorExtensions = useMemo(() => {
    return [...bindingExtensions, ...awarenessExts]
  }, [bindingExtensions, awarenessExts])

  const { previewScrollPct, previewAnchorLine, handleEditorScroll, handlePreviewScroll, lockActive } = useScrollSync(editorRef)
  const { runCommand } = useMarkdownCommands(editorRef)

  const handleToolbarCommand = useCallback(
    (cmd: string, value?: number) => {
      runCommand(cmd as MarkdownCommand, value)
    },
    [runCommand],
  )

  useEffect(() => {
    if (!viewModeHydrated) return
    if (forcedView) return
    if (hasPersistentViewMode) return
    if (!initialViewProp) return
    if (viewMode === initialViewProp) return
    safeExecute('set initial view mode', () => setViewMode(initialViewProp))
  }, [forcedView, hasPersistentViewMode, initialViewProp, setViewMode, viewMode, viewModeHydrated])

  const { uploadFiles, uploadStatus } = useEditorUploads(documentId, readOnly, emitReadOnlyWarning)
  const uploadFilesRef = useRef(uploadFiles)
  useEffect(() => {
    uploadFilesRef.current = uploadFiles
  }, [uploadFiles])

  const handleTaskToggle = useCallback((lineNumber: number, checked: boolean) => {
    if (readOnly) {
      emitReadOnlyWarning()
      return
    }
    if (!Number.isInteger(lineNumber) || lineNumber < 1) return
    const ytext = doc.getText('content')
    const text = ytext.toString()
    let offset = 0
    let currentLine = 1
    while (currentLine < lineNumber) {
      const nextNewline = text.indexOf('\n', offset)
      if (nextNewline === -1) return
      offset = nextNewline + 1
      currentLine += 1
    }
    const nextNewline = text.indexOf('\n', offset)
    const lineEnd = nextNewline === -1 ? text.length : nextNewline
    const lineText = text.slice(offset, lineEnd)
    const taskMatch = lineText.match(/^(\s*(?:>\s*)*(?:[-*+]|\d+[.)])\s*\[)([ xX])(\]\s*)(.*)$/)
    if (!taskMatch) return
    const [, prefix, currentChar, closing, rest] = taskMatch
    const nextChar = checked ? 'x' : ' '
    if (currentChar === nextChar) return
    const newLine = `${prefix}${nextChar}${closing}${rest}`
    doc.transact(() => {
      const y = doc.getText('content')
      y.delete(offset, lineText.length)
      y.insert(offset, newLine)
    })
  }, [doc, readOnly, emitReadOnlyWarning])

  const isThisEditorActive = useCallback(() => {
    const ed = editorRef.current
    if (!ed) return false
    return activeEditor === ed
  }, [activeEditor, editorRef])

  const ensureThisEditorActive = useCallback(() => {
    const ed = editorRef.current
    if (!ed) return
    if (activeEditor !== ed) setEditor(ed)
  }, [activeEditor, editorRef, setEditor])

  // Handle editor view creation
  const handleEditorViewCreated = useCallback((view: EditorView) => {
    setEditorView(view)

    // Register editor
    unregisterEditorRef.current?.()
    unregisterEditorRef.current = registerEditor(view)

    // Set up scroll listener for split view sync
    const scrollHandler = () => {
      if (!syncScrollRef.current || viewRef.current !== 'split') return
      handleEditorScroll()
    }
    view.scrollDOM.addEventListener('scroll', scrollHandler)

    // Set up mosaic scroll sync
    const mosaicScrollHandler = () => {
      const groupId = mosaicGroupIdRef.current
      if (!groupId) return
      if (!syncScrollRef.current) return
      if (suppressMosaicEmitRef.current) return
      if (mosaicScrollRafRef.current != null) return

      mosaicScrollRafRef.current = window.requestAnimationFrame(() => {
        mosaicScrollRafRef.current = null
        try {
          const block = view.lineBlockAtHeight(view.scrollDOM.scrollTop)
          const line = view.state.doc.lineAt(block.from).number
          if (!Number.isFinite(line) || line < 1) return
          dispatchMosaicScrollSync({ groupId, source: 'editor', line })
        } catch (error) {
          logEditorError('mosaic scroll sync emit', error)
        }
      })
    }
    view.scrollDOM.addEventListener('scroll', mosaicScrollHandler)

    // Set up paste handler
    const pasteHandler = async (event: ClipboardEvent) => {
      try {
        const clipboardData = event.clipboardData
        const fileList = clipboardData?.files
        if (!fileList || fileList.length === 0) return

        const files = Array.from(fileList).filter((file) => file.size > 0)
        if (files.length === 0) return

        event.preventDefault()
        event.stopPropagation()
        const handler = uploadFilesRef.current
        if (handler) {
          await handler(files)
        }
      } catch (error) {
        logEditorError('paste handler', error)
      }
    }
    view.contentDOM.addEventListener('paste', pasteHandler)

    // Apply vim mode if enabled
    if (isVimMode) {
      enableVimMode(view)
    }

    // Store cleanup function on view
    ;(view as any).__cleanup = () => {
      view.scrollDOM.removeEventListener('scroll', scrollHandler)
      view.scrollDOM.removeEventListener('scroll', mosaicScrollHandler)
      view.contentDOM.removeEventListener('paste', pasteHandler)
    }
  }, [setEditorView, registerEditor, handleEditorScroll, isVimMode])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      const view = editorRef.current
      if (view) {
        safeExecute('cleanup editor', () => (view as any).__cleanup?.())
      }
      safeExecute('unregister editor', () => unregisterEditorRef.current?.())
      unregisterEditorRef.current = null
      safeExecute('cancel mosaic scroll raf', () => {
        if (mosaicScrollRafRef.current != null) {
          window.cancelAnimationFrame(mosaicScrollRafRef.current)
          mosaicScrollRafRef.current = null
        }
      })
      safeExecute('cancel mosaic suppress timeout', () => {
        if (suppressMosaicTimeoutRef.current != null) {
          window.clearTimeout(suppressMosaicTimeoutRef.current)
          suppressMosaicTimeoutRef.current = null
        }
        suppressMosaicEmitRef.current = false
      })
    }
  }, [editorRef])

  // Listen for mosaic scroll sync from preview
  useEffect(() => {
    if (typeof window === 'undefined') return
    if (!scrollSyncGroupId) return

    const handler = (event: Event) => {
      try {
        if (!syncScrollRef.current) return
        const detail = (event as CustomEvent<MosaicScrollSyncDetail>).detail
        if (!detail || detail.source !== 'preview') return
        if (detail.groupId !== scrollSyncGroupId) return
        const line = detail.line
        if (!Number.isFinite(line) || (line as number) < 1) return

        const view = editorRef.current
        if (!view) return

        const maxLine = view.state.doc.lines
        const clamped = maxLine ? Math.min(maxLine, Math.max(1, Math.floor(line as number))) : Math.max(1, Math.floor(line as number))

        if (suppressMosaicTimeoutRef.current != null) {
          window.clearTimeout(suppressMosaicTimeoutRef.current)
          suppressMosaicTimeoutRef.current = null
        }
        suppressMosaicEmitRef.current = true

        try {
          const lineInfo = view.state.doc.line(clamped)
          view.dispatch({
            effects: EditorView.scrollIntoView(lineInfo.from, { y: 'start' }),
          })
        } finally {
          suppressMosaicTimeoutRef.current = window.setTimeout(() => {
            suppressMosaicTimeoutRef.current = null
            suppressMosaicEmitRef.current = false
          }, 120)
        }
      } catch (error) {
        logEditorError('mosaic scroll sync receive', error)
      }
    }

    window.addEventListener(MOSAIC_SCROLL_SYNC_EVENT, handler as EventListener)
    return () => {
      window.removeEventListener(MOSAIC_SCROLL_SYNC_EVENT, handler as EventListener)
    }
  }, [editorRef, scrollSyncGroupId])

  const toggleVim = useCallback(() => {
    const next = !isVimMode
    setIsVimMode(next)
    if (typeof window !== 'undefined') localStorage.setItem('editorVimMode', String(next))

    const view = editorRef.current
    if (!view) return

    if (next) {
      enableVimMode(view)
    } else {
      disableVimMode(view)
    }
  }, [isVimMode, editorRef])

  const handleFileUpload = useCallback(() => {
    if (readOnly) {
      emitReadOnlyWarning()
      return
    }
    ensureThisEditorActive()
    if (fileInputRef.current) fileInputRef.current.click()
  }, [emitReadOnlyWarning, readOnly, ensureThisEditorActive])

  const Toolbar = useMemo(() => (
    <EditorToolbar
      onCommand={handleToolbarCommand}
      viewMode={view as ViewMode}
      syncScroll={syncScroll}
      onSyncScrollToggle={() => setSyncScroll((s) => !s)}
      syncScrollAvailable={Boolean(scrollSyncGroupId)}
      isVimMode={isVimMode}
      onVimModeToggle={toggleVim}
      onFileUpload={readOnly ? undefined : handleFileUpload}
      readOnly={readOnly}
    />
  ), [handleToolbarCommand, view, syncScroll, scrollSyncGroupId, isVimMode, toggleVim, handleFileUpload, readOnly])

  const shortcutToggleSync = useCallback(() => {
    if (!isThisEditorActive()) return
    setSyncScroll((value) => !value)
  }, [isThisEditorActive])

  const shortcutToggleVim = useCallback(() => {
    if (!isThisEditorActive()) return
    toggleVim()
  }, [isThisEditorActive, toggleVim])

  const shortcutUpload = useCallback(() => {
    if (!isThisEditorActive()) return
    handleFileUpload()
  }, [handleFileUpload, isThisEditorActive])

  useShortcut('editor.sync-scroll.toggle', shortcutToggleSync)
  useShortcut('editor.vim.toggle', shortcutToggleVim)
  useShortcut('editor.upload.trigger', shortcutUpload)

  const onPreviewNavigate = useCallback(async (target: string) => {
    if (isShareLink && shareScope === 'document') {
      toast.info('This share link is for a single document.')
      return
    }
    const uuidRe = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
    let id = target
    if (!uuidRe.test(target) && !shareToken) {
      try {
        const resp = await listDocuments({ query: target })
        const items = (resp.items ?? []) as unknown as Array<{ id: string; title: string }>
        const exact = items.find((r) => (r.title || '').toLowerCase() === target.toLowerCase())
        const pick = exact || items[0]
        if (pick?.id) id = pick.id
      } catch (error) {
        logEditorError('lookup wiki link target', error)
      }
    }
    if (uuidRe.test(id)) {
      try {
        navigate({
          to: '/document/$id',
          params: { id },
          search: (prev: Record<string, string | string[] | undefined>) => {
            if (!shareToken) return prev
            const next: Record<string, string | string[] | undefined> = { ...(prev || {}), token: shareToken }
            if (shareScope) next.shareScope = shareScope
            if (isShareMount) next.shareMount = '1'
            return next
          },
        })
      } catch (error) {
        logEditorError('navigate to document from preview', error)
        const qs = shareToken ? `?token=${encodeURIComponent(shareToken)}` : ''
        window.location.href = `/document/${id}${qs}`
      }
    }
  }, [isShareLink, isShareMount, navigate, shareScope, shareToken])

  const handleEditorDropFiles = useCallback(
    async (files: File[]) => {
      ensureThisEditorActive()
      await uploadFiles(files)
    },
    [ensureThisEditorActive, uploadFiles],
  )

  return (
    <div
      className="relative flex h-full flex-1 min-h-0 flex-col"
      onMouseDownCapture={ensureThisEditorActive}
      onFocusCapture={ensureThisEditorActive}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={async (e) => {
          ensureThisEditorActive()
          const files = Array.from(e.currentTarget.files || [])
          await uploadFiles(files)
          safeExecute('reset file input', () => {
            e.currentTarget.value = ''
          })
        }}
      />

      <EditorLayout
        isMobile={isMobile}
        view={view as ViewMode}
        extraRight={extraRight}
        embedded={embedded}
        toolbar={Toolbar}
        toolbarOpen={toolbarOpen}
        onToolbarOpenChange={setToolbarOpen}
        isDarkMode={isDarkMode}
        readOnly={readOnly}
        onEditorDropFiles={handleEditorDropFiles}
        onEditorViewCreated={handleEditorViewCreated}
        editorExtensions={editorExtensions}
        editorRef={editorRef}
        syncScroll={syncScroll}
        onPreviewScroll={handlePreviewScroll}
        previewScrollPct={previewScrollPct}
        previewAnchorLine={previewAnchorLine}
        lockActive={lockActive}
        onPreviewNavigate={onPreviewNavigate}
        documentId={documentId}
        onToggleTask={handleTaskToggle}
        previewContentOverride={previewOverride}
        content={boundText}
        vimStatusBarRef={vimStatusBarRef}
        showVimStatusBar={isVimMode}
        uploadStatus={uploadStatus}
        renderPreview={renderPreview}
        conflictControls={conflictControls}
        conflictBadgeText={conflictBadgeText}
        conflictHunkWidgets={conflictHunkWidgets}
        conflictView={conflictView}
      />

      <CursorDisplay awareness={awareness} className={embedded ? 'top-12' : undefined} />
    </div>
  )
}

export default MarkdownEditor
