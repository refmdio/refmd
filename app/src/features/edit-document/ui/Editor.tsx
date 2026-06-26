import type { OnMount } from '@monaco-editor/react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import type * as monacoNs from 'monaco-editor'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import type { Awareness } from 'y-protocols/awareness'
import * as Y from 'yjs'

import { useShareToken } from '@/shared/contexts/share-token-context'
import { useTheme } from '@/shared/contexts/theme-context'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { useShortcut } from '@/shared/hooks/use-shortcut'
import type { ViewMode } from '@/shared/types/view-mode'

import {
  documentCommentsQuery,
  listDocuments,
} from '@/entities/document'

import {
  CommentsPanel,
  findUnknownCommentMarkers,
  stripCommentMarkers,
} from '@/features/document-comments'
import {
  findCommentMarkerRange,
  findCommentThreadRange,
  getCommentThreadLine,
} from '@/features/document-comments/lib/thread-range'
import { useAwarenessStyles } from '@/features/edit-document/hooks/useAwarenessStyles'
import { markDocumentContentDirty } from '@/features/edit-document/hooks/useCollaborativeDocument'
import { useEditorUploads } from '@/features/edit-document/hooks/useEditorUploads'
import { useMarkdownCommands, type MarkdownCommand } from '@/features/edit-document/hooks/useMarkdownCommands'
import { useMonacoBinding } from '@/features/edit-document/hooks/useMonacoBinding'
import { useScrollSync } from '@/features/edit-document/hooks/useScrollSync'
import { ensureRefmdThemes, REFMD_DARK_THEME, REFMD_LIGHT_THEME } from '@/features/edit-document/lib/monaco/theme'
import { registerWikiLinkCompletion } from '@/features/edit-document/lib/monaco/wiki-link-provider'
import { useEditorContext } from '@/features/edit-document/model/editor-context'
import { useViewContext } from '@/features/edit-document/model/view-context'
import { useDocumentEditorPlugins, type DocumentEditorApi, type DocumentEditorDecorationInput, type DocumentEditorDocumentApi, type DocumentEditorRange, type DocumentEditorSelection } from '@/features/plugins'
import type { DocumentEditorPaneHostState } from '@/features/plugins/model/useDocumentEditorPlugins'

import { loadMonacoVim } from '../lib/monaco/vim-loader'

import CursorDisplay from './CursorDisplay'
import EditorLayout from './EditorLayout'
import type { PreviewPaneProps } from './PreviewPane'
import EditorToolbar from './Toolbar'

const logEditorError = (scope: string, error: unknown) => {
  if (error instanceof Error && /InstantiationService has been disposed/i.test(error.message)) {
    return
  }
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

const EMPTY_COMMENT_COMPOSER_STATE = {
  composerOpen: false,
  newComment: '',
  newTags: '',
  newTagsOpen: false,
}

type RefmdEditorInstance = monacoNs.editor.IStandaloneCodeEditor & {
  __disposeChange?: () => void
  __disposeScroll?: () => void
  __disposePaste?: () => void
  __disposeWiki?: () => void
  __disposeCursor?: () => void
  __disposeMonacoMd?: () => void
  __disposeKeydown?: () => void
  __disposeDirtyTracker?: () => void
  __readOnlyOverlay?: {
    widget: monacoNs.editor.IOverlayWidget
    domNode: HTMLElement
  }
  __monaco?: typeof monacoNs
}

export type MarkdownEditorProps = {
  doc: Y.Doc
  awareness: Awareness
  connected: boolean
  initialView?: ViewMode
  forcedView?: ViewMode
  embedded?: boolean
  userName?: string
  userId?: string
  documentId: string
  documentTitle?: string | null
  documentType?: string | null
  documentEditorPluginsEnabled?: boolean
  onDocumentEditorPaneHostChange?: (host: DocumentEditorPaneHostState | null) => void
  commentsOpen?: boolean
  onCommentsOpenChange?: (open: boolean) => void
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
    initialView: initialViewProp = 'split',
    forcedView,
    embedded = false,
    userId,
    userName,
    documentId,
    documentTitle,
    documentType,
    documentEditorPluginsEnabled = true,
    onDocumentEditorPaneHostChange,
    commentsOpen = false,
    onCommentsOpenChange,
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
  const brandedMonacoTheme = isDarkMode ? REFMD_DARK_THEME : REFMD_LIGHT_THEME
  const monacoTheme = brandedMonacoTheme
  const view = forcedView ?? viewMode
  const [isVimMode, setIsVimMode] = useState<boolean>(() => typeof window !== 'undefined' && localStorage.getItem('editorVimMode') === 'true')
  const [syncScroll, setSyncScroll] = useState<boolean>(true)
  const [toolbarOpen, setToolbarOpen] = useState(false)
  const [editorMountNonce, setEditorMountNonce] = useState(0)
  const [activeCommentThreadId, setActiveCommentThreadId] = useState<
    string | null
  >(null)
  const [commentComposerState, setCommentComposerState] = useState(
    EMPTY_COMMENT_COMPOSER_STATE,
  )
  const readOnlyWarningRef = useRef(0)
  const emitReadOnlyWarning = useCallback(() => {
    if (!readOnly) return
    const now = Date.now()
    if (now - readOnlyWarningRef.current < 1500) return
    readOnlyWarningRef.current = now
    toast.info('Document is read-only')
  }, [readOnly])
  const syncScrollRef = useRef<boolean>(true)
  useEffect(() => { syncScrollRef.current = syncScroll }, [syncScroll])
  const vimModeRef = useRef<{ dispose: () => void } | null>(null)
  const vimStatusBarRef = useRef<HTMLDivElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const viewRef = useRef<ViewMode>(forcedView ?? initialViewProp)
  useEffect(() => {
    viewRef.current = view as ViewMode
  }, [view])
  const { onMount: onMonacoMount, text: boundText, editorRef, disposeBinding } = useMonacoBinding({
    doc,
    awareness,
    language: 'markdown',
    onTextChange: () => {},
  })
  const commentsQuery = useQuery(documentCommentsQuery(documentId, { token: shareToken }))
  useEffect(() => {
    setCommentComposerState(EMPTY_COMMENT_COMPOSER_STATE)
  }, [documentId])
  const commentThreads = useMemo(
    () => commentsQuery.data?.threads ?? [],
    [commentsQuery.data?.threads],
  )
  const commentMarkerStrings = useMemo(
    () => commentThreads.map((thread) => thread.marker),
    [commentThreads],
  )
  const unknownCommentMarkerKey = useMemo(() => {
    const markers = findUnknownCommentMarkers(boundText, commentMarkerStrings)
    return markers.length ? markers.sort().join('\n') : ''
  }, [boundText, commentMarkerStrings])
  const commentMetadataRefetchRef = useRef({ key: '', attempts: 0 })
  useEffect(() => {
    if (!unknownCommentMarkerKey) {
      commentMetadataRefetchRef.current = { key: '', attempts: 0 }
      return
    }

    const state = commentMetadataRefetchRef.current
    if (state.key !== unknownCommentMarkerKey) {
      commentMetadataRefetchRef.current = {
        key: unknownCommentMarkerKey,
        attempts: 0,
      }
    }
    const current = commentMetadataRefetchRef.current
    if (commentsQuery.isFetching || current.attempts >= 5) return

    const delay = Math.min(1000, 150 * 2 ** current.attempts)
    const timer = window.setTimeout(() => {
      current.attempts += 1
      void commentsQuery.refetch()
    }, delay)

    return () => window.clearTimeout(timer)
  }, [
    commentsQuery.dataUpdatedAt,
    commentsQuery.isFetching,
    commentsQuery.refetch,
    unknownCommentMarkerKey,
  ])
  const previewCommentContent = previewOverride ?? boundText
  const renderedPreviewContent = useMemo(
    () => stripCommentMarkers(previewCommentContent, commentMarkerStrings),
    [commentMarkerStrings, previewCommentContent],
  )
  const previewCommentMarkers = useMemo<
    NonNullable<PreviewPaneProps['commentMarkers']>
  >(
    () =>
      commentThreads
        .map((thread) => {
          const lineNumber = getCommentThreadLine(thread, previewCommentContent)
          if (!lineNumber) return null
          return {
            threadId: thread.id,
            lineNumber,
            resolved: Boolean(thread.resolvedAt),
            active: activeCommentThreadId === thread.id,
          }
        })
        .filter((marker): marker is NonNullable<typeof marker> =>
          Boolean(marker),
        ),
    [activeCommentThreadId, commentThreads, previewCommentContent],
  )
  const handleSelectCommentThread = useCallback(
    (threadId: string | null) => {
      setActiveCommentThreadId(threadId)
      if (threadId) onCommentsOpenChange?.(true)
    },
    [onCommentsOpenChange],
  )
  const unregisterEditorRef = useRef<null | (() => void)>(null)
  const focusDisposableRef = useRef<null | { dispose: () => void }>(null)
  const blurDisposableRef = useRef<null | { dispose: () => void }>(null)
  const pluginDecorationIdsRef = useRef<Map<string, string[]>>(new Map())
  const pluginHiddenRangeSourcesRef = useRef<Map<string, object>>(new Map())

  const cleanupEditorInstance = useCallback(
    (editor: RefmdEditorInstance | null | undefined) => {
      safeExecute('dispose change listener', () => editor?.__disposeChange?.())
      safeExecute('dispose scroll listener', () => editor?.__disposeScroll?.())
      safeExecute('dispose paste handler', () => editor?.__disposePaste?.())
      safeExecute('dispose wiki handler', () => editor?.__disposeWiki?.())
      safeExecute('dispose cursor handler', () => editor?.__disposeCursor?.())
      safeExecute('dispose monaco markdown handler', () => editor?.__disposeMonacoMd?.())
      safeExecute('dispose keydown handler', () => editor?.__disposeKeydown?.())
      safeExecute('dispose dirty tracker', () => editor?.__disposeDirtyTracker?.())
      safeExecute('dispose plugin decorations', () => {
        for (const ids of pluginDecorationIdsRef.current.values()) {
          try {
            editor?.deltaDecorations(ids, [])
          } catch {
            /* noop */
          }
        }
        pluginDecorationIdsRef.current.clear()
      })
      safeExecute('dispose plugin hidden ranges', () => {
        const setHiddenAreas = (editor as any)?.setHiddenAreas
        if (typeof setHiddenAreas !== 'function') {
          pluginHiddenRangeSourcesRef.current.clear()
          return
        }
        for (const source of pluginHiddenRangeSourcesRef.current.values()) {
          try {
            setHiddenAreas.call(editor, [], source)
          } catch {
            /* noop */
          }
        }
        pluginHiddenRangeSourcesRef.current.clear()
      })
      safeExecute('dispose read-only overlay', () => {
        if (editor?.__readOnlyOverlay) {
          try { editor.removeOverlayWidget(editor.__readOnlyOverlay.widget) } catch {}
          try { editor.__readOnlyOverlay.domNode.remove() } catch {}
          delete editor.__readOnlyOverlay
        }
        if (editor && '__monaco' in editor) {
          delete editor.__monaco
        }
      })
    },
    [],
  )

  const isThisEditorActive = useCallback(() => {
    const ed = editorRef.current
    if (!ed) return false
    return activeEditor === ed
  }, [activeEditor, editorRef])

  const ensureThisEditorActive = useCallback(() => {
    const ed = editorRef.current as monacoNs.editor.IStandaloneCodeEditor | null
    if (!ed) return
    if (activeEditor !== ed) setEditor(ed as any)
  }, [activeEditor, editorRef, setEditor])
  const disableVimMode = useCallback(() => {
    if (vimModeRef.current) {
      safeExecute('disable vim mode', () => vimModeRef.current?.dispose())
      vimModeRef.current = null
    }
    if (vimStatusBarRef.current) {
      vimStatusBarRef.current.textContent = ''
    }
  }, [])
  const enableVimMode = useCallback(async (targetEditor?: monacoNs.editor.IStandaloneCodeEditor) => {
    const editorInstance = targetEditor ?? (editorRef.current as monacoNs.editor.IStandaloneCodeEditor | null)
    const statusBar = vimStatusBarRef.current
    if (!editorInstance || !statusBar) return
    disableVimMode()
    try {
      const { initVimMode } = await loadMonacoVim()
      statusBar.textContent = ''
      vimModeRef.current = initVimMode(editorInstance, statusBar)
      editorInstance.focus()
    } catch (error) {
      logEditorError('enable vim mode', error)
    }
  }, [disableVimMode, editorRef])
  const { previewScrollPct, previewAnchorLine, handleEditorScroll, handlePreviewScroll, onEditorContentChange, onCaretAtEndChange, lockActive } = useScrollSync(editorRef)
  const { runCommand } = useMarkdownCommands(editorRef)
  const handleToolbarCommand = useCallback(
    (cmd: string, value?: number) => {
      runCommand(cmd as MarkdownCommand, value)
    },
    [runCommand],
  )
  // Wire the actual callback now that hook is ready
  ;(onMonacoMount as any)._onTextChange = onEditorContentChange
  ;(onMonacoMount as any)._onCaretAtEnd = onCaretAtEndChange
  useEffect(() => {
    if (!viewModeHydrated) return
    if (forcedView) return
    if (hasPersistentViewMode) return
    if (!initialViewProp) return
    if (viewMode === initialViewProp) return
    safeExecute('set initial view mode', () => setViewMode(initialViewProp))
  }, [forcedView, hasPersistentViewMode, initialViewProp, setViewMode, viewMode, viewModeHydrated])

  useAwarenessStyles(awareness, { userId, userName })

  const { uploadFiles, uploadStatus } = useEditorUploads(documentId, readOnly, emitReadOnlyWarning)
  const uploadFilesRef = useRef(uploadFiles)
  useEffect(() => {
    uploadFilesRef.current = uploadFiles
  }, [uploadFiles])

  const setReadOnlyOverlay = useCallback(
    (
      editor: (monacoNs.editor.IStandaloneCodeEditor & { __readOnlyOverlay?: { widget: monacoNs.editor.IOverlayWidget; domNode: HTMLElement }; __monaco?: typeof monacoNs }) | undefined,
      monacoInstance: typeof monacoNs | undefined,
      enabled: boolean,
    ) => {
      if (!editor || !monacoInstance) return
      const existing = editor.__readOnlyOverlay
      if (enabled) {
        if (existing) return
        const domNode = document.createElement('div')
        domNode.className = 'pointer-events-none select-none text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground bg-background/85 border border-border/60 rounded-full px-3 py-1 shadow-sm'
        domNode.textContent = 'Read-only'
        const widget: monacoNs.editor.IOverlayWidget = {
          getId: () => 'read-only-overlay',
          getDomNode: () => domNode,
          getPosition: () => ({
            preference: monacoInstance.editor.OverlayWidgetPositionPreference.TOP_RIGHT_CORNER,
          }),
        }
        editor.addOverlayWidget(widget)
        editor.__readOnlyOverlay = { widget, domNode }
      } else if (existing) {
        try { editor.removeOverlayWidget(existing.widget) } catch {}
        try { existing.domNode.remove() } catch {}
        delete editor.__readOnlyOverlay
      }
    },
    [],
  )

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
      if (nextNewline === -1) {
        return
      }
      offset = nextNewline + 1
      currentLine += 1
    }
    const nextNewline = text.indexOf('\n', offset)
    const lineEnd = nextNewline === -1 ? text.length : nextNewline
    const lineText = text.slice(offset, lineEnd)
    // Allow optional blockquote and ordered list prefixes before the task checkbox
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
    markDocumentContentDirty(documentId, doc.getText('content').toString())
  }, [doc, documentId, readOnly, emitReadOnlyWarning])

  const handleBeforeMount = useCallback((monaco: Parameters<OnMount>[1]) => {
    ensureRefmdThemes(monaco as any)
    monaco.editor.setTheme(brandedMonacoTheme)
  }, [brandedMonacoTheme])

  const handleMount: OnMount = useCallback((editor, monaco) => {
    // First, bind Monaco to Yjs via hook
    onMonacoMount(editor, monaco)
    ;(editor as any).__monaco = monaco
    setReadOnlyOverlay(editor as any, monaco as any, readOnly)
    let userEditIntent = false
    const markDirtyFromModel = () => {
      if (readOnly) return
      const value = editor.getModel()?.getValue()
      if (typeof value === 'string') {
        markDocumentContentDirty(documentId, value)
      }
    }
    ;(editor as any).__refmdMarkDirty = markDirtyFromModel
    try {
      const modelChangeDispose = editor.onDidChangeModelContent(() => {
        if (!userEditIntent) return
        markDirtyFromModel()
      })
      ;(editor as any).__disposeDirtyTracker = () => safeExecute('dispose dirty tracker', () => modelChangeDispose.dispose())
    } catch (error) {
      logEditorError('register dirty tracker', error)
    }
    // Register wiki-link completion provider
    try {
      const disp = registerWikiLinkCompletion(monaco as any)
      ;(editor as any).__disposeWiki = () => safeExecute('dispose wiki completion', () => disp?.dispose?.())
    } catch (error) {
      logEditorError('register wiki completion', error)
    }

    // Activate monaco-markdown extension for lists/enter/tab/completions (lazy load)
    ;(async () => {
      try {
        const mod = await import('monaco-markdown')
        const ext = new mod.MonacoMarkdownExtension()
        ext.activate(editor as any)
        ;(editor as any).__disposeMonacoMd = () => {}
      } catch (error) {
        logEditorError('load monaco-markdown', error)
      }
    })()

    const cursorDispose = editor.onDidChangeCursorSelection((_e) => {})
    ;(editor as any).__disposeCursor = () => safeExecute('dispose cursor listener', () => cursorDispose.dispose())

    const shouldWarnForKey = (ev: any) => {
      if (!readOnly) return false
      const native = ev?.browserEvent ?? ev
      if (!native) return false
      const { ctrlKey, metaKey, altKey } = native
      if (ctrlKey || metaKey || altKey) return false
      const key = native.key ?? native.code ?? ''
      if (key === ' ' || key === 'Spacebar') return true
      const editingKeys = ['Backspace', 'Delete', 'Enter', 'Tab']
      if (editingKeys.includes(key)) return true
      if (typeof key === 'string' && key.length === 1) return true
      return false
    }

    // Pre-lock preview to bottom when user hits Enter at file end
    try {
      const keydownDispose = editor.onKeyDown((e: any) => {
        try {
          if (shouldWarnForKey(e)) {
            emitReadOnlyWarning()
            return
          }
          if (!readOnly) {
            userEditIntent = true
            ;(editor as any).__refmdUserEditIntent = true
          }
          const KeyCode = (monaco as any)?.KeyCode
          const isEnter = KeyCode ? e.keyCode === KeyCode.Enter : e.code === 'Enter' || e.keyCode === 13
          if (!isEnter) return
          const model = editor.getModel()
          const pos = editor.getPosition()
          if (!model || !pos) return
          const lastLine = model.getLineCount()
          const atLastLine = pos.lineNumber >= lastLine
          if (!atLastLine) return
          const maxCol = model.getLineMaxColumn(lastLine)
          const atEndOfDoc = pos.column >= maxCol
          if (atEndOfDoc) {
            safeExecute('handle enter at end of doc', () => onEditorContentChange())
          }
        } catch (error) {
          logEditorError('keydown handler', error)
        }
      })
      ;(editor as any).__disposeKeydown = () => safeExecute('dispose keydown listener', () => keydownDispose.dispose())
    } catch (error) {
      logEditorError('register keydown handler', error)
    }

    // Hook editor scroll for sync
    const scrollDispose = editor.onDidScrollChange?.((e) => {
      if (!syncScrollRef.current || viewRef.current !== 'split') return
      handleEditorScroll(e)
    })
    ;(editor as any).__disposeScroll = () => safeExecute('dispose scroll listener', () => scrollDispose?.dispose?.())

    // Handle paste (Ctrl+V) with files from clipboard
    const dom = editor.getDomNode() as HTMLElement | null
    const pasteHandler = async (event: ClipboardEvent) => {
      try {
        const editorDomNode = dom
        const target = event.target as HTMLElement | null
        if (!editorDomNode || !target || !editorDomNode.contains(target)) return

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

    if (typeof document !== 'undefined') {
      document.addEventListener('paste', pasteHandler as any, true)
    }

    ;(editor as any).__disposePaste = () => {
      safeExecute('remove document paste listener', () => {
        if (typeof document !== 'undefined') {
          document.removeEventListener('paste', pasteHandler as any, true)
        }
      })
    }

    // Apply vim if enabled
    if (isVimMode) {
      void enableVimMode(editor)
    }
  }, [onMonacoMount, isVimMode, syncScroll, handleEditorScroll, emitReadOnlyWarning, readOnly, setReadOnlyOverlay, enableVimMode, brandedMonacoTheme, documentId])

  useEffect(() => {
    const editorInstance = editorRef.current as (monacoNs.editor.IStandaloneCodeEditor & { __readOnlyOverlay?: { widget: monacoNs.editor.IOverlayWidget; domNode: HTMLElement }; __monaco?: typeof monacoNs }) | null
    if (!editorInstance) return
    const monacoInstance = editorInstance.__monaco
    setReadOnlyOverlay(editorInstance, monacoInstance, readOnly)
  }, [readOnly, setReadOnlyOverlay])

  useEffect(() => {
    const editorInstance = editorRef.current as (monacoNs.editor.IStandaloneCodeEditor & { __monaco?: typeof monacoNs }) | null
    const monacoInstance = editorInstance?.__monaco
    if (!monacoInstance) return
    ensureRefmdThemes(monacoInstance)
    monacoInstance.editor.setTheme(brandedMonacoTheme)
  }, [brandedMonacoTheme, editorRef])

  useEffect(() => () => {
    cleanupEditorInstance(editorRef.current as RefmdEditorInstance | null)
    safeExecute('dispose editor focus listener', () => focusDisposableRef.current?.dispose())
    focusDisposableRef.current = null
    safeExecute('dispose editor blur listener', () => blurDisposableRef.current?.dispose())
    blurDisposableRef.current = null
    safeExecute('unregister editor instance', () => unregisterEditorRef.current?.())
    unregisterEditorRef.current = null
    disableVimMode()
  }, [cleanupEditorInstance, editorRef, disableVimMode])

  const toggleVim = useCallback(async () => {
    const next = !isVimMode
    setIsVimMode(next)
    if (typeof window !== 'undefined') localStorage.setItem('editorVimMode', String(next))
    if (next) {
      await enableVimMode()
    } else {
      disableVimMode()
    }
  }, [isVimMode, enableVimMode, disableVimMode])

  const handleFileUpload = useCallback(() => {
    if (readOnly) {
      emitReadOnlyWarning()
      return
    }
    ensureThisEditorActive()
    if (fileInputRef.current) fileInputRef.current.click()
  }, [emitReadOnlyWarning, readOnly, ensureThisEditorActive])

  // uploadFiles provided by hook

  // View mode is now controlled via ViewContext

  const Toolbar = useMemo(() => (
    <EditorToolbar
      onCommand={handleToolbarCommand}
      viewMode={view as ViewMode}
      syncScroll={syncScroll}
      onSyncScrollToggle={() => setSyncScroll((s) => !s)}
      isVimMode={isVimMode}
      onVimModeToggle={toggleVim}
      onFileUpload={readOnly ? undefined : handleFileUpload}
      readOnly={readOnly}
    />
  ), [handleToolbarCommand, view, syncScroll, isVimMode, toggleVim, handleFileUpload, readOnly])

  const shortcutToggleSync = useCallback(() => {
    if (!isThisEditorActive()) return
    setSyncScroll((value) => !value)
  }, [isThisEditorActive])
  const shortcutToggleVim = useCallback(() => {
    if (!isThisEditorActive()) return
    void toggleVim()
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

  // Ensure Monaco relayouts when view/layout changes or container resizes
  useEffect(() => {
    const ed = editorRef.current as monacoNs.editor.IStandaloneCodeEditor | null
    if (!ed) return
    const relayoutToContainer = () => {
      safeExecute('editor relayout', () => {
        const container = (ed as any).getContainerDomNode?.() as HTMLElement | null
        const node = ed.getDomNode?.() as HTMLElement | null
        const target = container || node?.parentElement || node
        if (!target) {
          ed.layout()
          return
        }
        const rect = target.getBoundingClientRect()
        if (!rect.width || !rect.height) {
          ed.layout()
          return
        }
        ed.layout({ width: rect.width, height: rect.height })
      })
    }
    // immediate relayout on view change
    relayoutToContainer()
    // also schedule once after transition
    const t = setTimeout(relayoutToContainer, 120)
    // observe parent size changes
    let ro: ResizeObserver | null = null
    try {
      const container = (ed as any).getContainerDomNode?.() as HTMLElement | null
      const node = ed.getDomNode() as HTMLElement | null
      const target = container || node?.parentElement || node
      if (target && 'ResizeObserver' in window) {
        ro = new ResizeObserver(() => relayoutToContainer())
        ro.observe(target)
      }
    } catch (error) {
      logEditorError('init resize observer', error)
    }
    // window resize
    window.addEventListener('resize', relayoutToContainer)
    return () => {
      clearTimeout(t)
      safeExecute('disconnect resize observer', () => {
        if (ro) ro.disconnect()
      })
      window.removeEventListener('resize', relayoutToContainer)
    }
  }, [editorMountNonce, view, editorRef])

  const handleEditorMount = useCallback(
    (editor: monacoNs.editor.IStandaloneCodeEditor, monaco: Parameters<OnMount>[1]) => {
      unregisterEditorRef.current?.()
      unregisterEditorRef.current = registerEditor(editor as any)
      safeExecute('dispose editor focus listener', () => focusDisposableRef.current?.dispose())
      safeExecute('dispose editor blur listener', () => blurDisposableRef.current?.dispose())
      focusDisposableRef.current = editor.onDidFocusEditorWidget(() => {
        try { setEditor(editor as any) } catch {}
      })
      blurDisposableRef.current = editor.onDidBlurEditorWidget(() => {
        // Keep last active editor; do not clear on blur to avoid losing target when clicking chrome.
      })
      handleMount(editor, monaco)
      setEditorMountNonce((n) => n + 1)
    },
    [handleMount, registerEditor, setEditor],
  )

  const handleEditorUnmount = useCallback(
    (editor: monacoNs.editor.IStandaloneCodeEditor | null) => {
      if (editor && editorRef.current && editorRef.current !== editor) return
      cleanupEditorInstance(editor as RefmdEditorInstance | null)
      unregisterEditorRef.current?.()
      unregisterEditorRef.current = null
      safeExecute('dispose editor focus listener', () => focusDisposableRef.current?.dispose())
      safeExecute('dispose editor blur listener', () => blurDisposableRef.current?.dispose())
      focusDisposableRef.current = null
      blurDisposableRef.current = null
      if (editor && activeEditor === editor) {
        safeExecute('clear active editor', () => setEditor(null))
      }
      disableVimMode()
      pluginDecorationIdsRef.current.clear()
      pluginHiddenRangeSourcesRef.current.clear()
      disposeBinding(editor)
      setEditorMountNonce((n) => n + 1)
    },
    [
      activeEditor,
      cleanupEditorInstance,
      disableVimMode,
      disposeBinding,
      editorRef,
      setEditor,
    ],
  )

  const handleEditorDropFiles = useCallback(
    async (files: File[]) => {
      ensureThisEditorActive()
      await uploadFiles(files)
    },
    [ensureThisEditorActive, uploadFiles],
  )

  const documentEditorApi = useMemo<DocumentEditorApi | null>(() => {
    const editorInstance = editorRef.current as (monacoNs.editor.IStandaloneCodeEditor & { __monaco?: typeof monacoNs }) | null
    const monacoInstance = editorInstance?.__monaco
    if (!editorInstance || !monacoInstance) return null

    const toRange = (range: DocumentEditorRange) =>
      new monacoInstance.Range(
        range.startLineNumber,
        range.startColumn,
        range.endLineNumber,
        range.endColumn,
      )

    const toSelection = (): DocumentEditorSelection | null => {
      const selection = editorInstance.getSelection()
      const model = editorInstance.getModel()
      if (!selection || !model) return null
      return {
        startLineNumber: selection.startLineNumber,
        startColumn: selection.startColumn,
        endLineNumber: selection.endLineNumber,
        endColumn: selection.endColumn,
        text: model.getValueInRange(selection),
        isEmpty: selection.isEmpty(),
      }
    }

    const applyEdits = (edits: Array<{ range: DocumentEditorRange; text: string; forceMoveMarkers?: boolean }>) => {
      if (readOnly) {
        emitReadOnlyWarning()
        return false
      }
      const nextEdits = edits
        .filter((edit) => edit && edit.range)
        .map((edit) => ({
          range: toRange(edit.range),
          text: String(edit.text ?? ''),
          forceMoveMarkers: edit.forceMoveMarkers !== false,
        }))
      if (!nextEdits.length) return false
      const applied = editorInstance.executeEdits('refmd-plugin', nextEdits)
      editorInstance.pushUndoStop()
      try {
        ;(editorInstance as any).__refmdUserEditIntent = true
        ;(editorInstance as any).__refmdMarkDirty?.()
      } catch {
        /* noop */
      }
      return applied
    }

    const applyTextAtSelection = (text: string) => {
      const selection = editorInstance.getSelection()
      if (!selection) return false
      return applyEdits([{ range: selection, text, forceMoveMarkers: true }])
    }

    return {
      focus: () => editorInstance.focus(),
      getSelection: toSelection,
      setSelection: (range) => {
        const next = toRange(range)
        editorInstance.setSelection(next)
        editorInstance.revealRangeInCenterIfOutsideViewport(next)
      },
      applyEdits,
      replaceSelection: applyTextAtSelection,
      insertText: applyTextAtSelection,
      revealLine: (line) => {
        if (!Number.isFinite(line)) return
        editorInstance.revealLineInCenterIfOutsideViewport(Math.max(1, Math.floor(line)))
      },
      revealRange: (range) => {
        editorInstance.revealRangeInCenterIfOutsideViewport(toRange(range))
      },
      getRangeFromOffset: (offset, length = 0) => {
        const model = editorInstance.getModel()
        if (!model) return null
        const contentLength = model.getValueLength()
        const startOffset = Math.max(0, Math.min(contentLength, Math.floor(offset)))
        const endOffset = Math.max(startOffset, Math.min(contentLength, startOffset + Math.max(0, Math.floor(length))))
        const start = model.getPositionAt(startOffset)
        const end = model.getPositionAt(endOffset)
        return {
          startLineNumber: start.lineNumber,
          startColumn: start.column,
          endLineNumber: end.lineNumber,
          endColumn: end.column,
        }
      },
      getOffsetFromPosition: (position) => {
        const model = editorInstance.getModel()
        if (!model) return null
        const lineNumber = Math.max(1, Math.floor(position.lineNumber))
        const column = Math.max(1, Math.floor(position.column))
        try {
          return model.getOffsetAt({ lineNumber, column })
        } catch {
          return null
        }
      },
      onSelectionChange: (callback) => {
        const disposable = editorInstance.onDidChangeCursorSelection(() => {
          callback(toSelection())
        })
        return () => {
          try {
            disposable.dispose()
          } catch {
            /* noop */
          }
        }
      },
      onGlyphMarginClick: (callback) => {
        const disposable = editorInstance.onMouseDown((event) => {
          if (
            event.target.type !==
            monacoInstance.editor.MouseTargetType.GUTTER_GLYPH_MARGIN
          ) {
            return
          }
          const lineNumber =
            event.target.position?.lineNumber ??
            event.target.range?.startLineNumber
          if (typeof lineNumber !== 'number' || !Number.isFinite(lineNumber)) {
            return
          }
          callback(Math.max(1, Math.floor(lineNumber)))
        })
        return () => {
          try {
            disposable.dispose()
          } catch {
            /* noop */
          }
        }
      },
      setDecorations: (ownerId, decorations) => {
        const owner = String(ownerId || 'default')
        const previous = pluginDecorationIdsRef.current.get(owner) ?? []
        const nextDecorations = decorations.map((decoration) => ({
          range: toRange(decoration.range),
          options: {
            className: decoration.className,
            inlineClassName: decoration.inlineClassName,
            glyphMarginClassName: decoration.glyphMarginClassName,
            hoverMessage: decoration.hoverMessage ? { value: decoration.hoverMessage } : undefined,
            overviewRuler: decoration.overviewRulerColor
              ? {
                  color: decoration.overviewRulerColor,
                  position: monacoInstance.editor.OverviewRulerLane.Right,
                }
              : undefined,
            minimap: decoration.minimapColor
              ? {
                  color: decoration.minimapColor,
                  position: monacoInstance.editor.MinimapPosition.Inline,
                }
              : undefined,
          },
        }))
        const nextIds = editorInstance.deltaDecorations(previous, nextDecorations)
        pluginDecorationIdsRef.current.set(owner, nextIds)
        return () => {
          const current = pluginDecorationIdsRef.current.get(owner)
          if (!current) return
          try {
            editorInstance.deltaDecorations(current, [])
          } catch {
            /* noop */
          }
          pluginDecorationIdsRef.current.delete(owner)
        }
      },
      setHiddenRanges: (ownerId, ranges) => {
        const owner = String(ownerId || 'default')
        const setHiddenAreas = (editorInstance as any).setHiddenAreas
        if (typeof setHiddenAreas !== 'function') {
          return () => {
            pluginHiddenRangeSourcesRef.current.delete(owner)
          }
        }

        const model = editorInstance.getModel()
        if (!model) return () => {}
        let source = pluginHiddenRangeSourcesRef.current.get(owner)
        if (!source) {
          source = {}
          pluginHiddenRangeSourcesRef.current.set(owner, source)
        }

        const lineCount = model.getLineCount()
        const nextRanges = ranges
          .map((item) => item?.range)
          .filter((range): range is DocumentEditorRange => Boolean(range))
          .map((range) => {
            const startLine = Math.min(lineCount, Math.max(1, Math.floor(range.startLineNumber)))
            const endLine = Math.min(lineCount, Math.max(startLine, Math.floor(range.endLineNumber || startLine)))
            return new monacoInstance.Range(startLine, 1, endLine, model.getLineMaxColumn(endLine))
          })

        try {
          setHiddenAreas.call(editorInstance, nextRanges, source)
        } catch {
          return () => {}
        }

        return () => {
          const current = pluginHiddenRangeSourcesRef.current.get(owner)
          if (current !== source) return
          try {
            setHiddenAreas.call(editorInstance, [], source)
          } catch {
            /* noop */
          }
          pluginHiddenRangeSourcesRef.current.delete(owner)
        }
      },
    }
  }, [editorMountNonce, editorRef, emitReadOnlyWarning, readOnly])

  useEffect(() => {
    if (!documentEditorApi) return
    const decorations = commentThreads
      .flatMap((thread) => {
        const range = findCommentThreadRange(thread, boundText, documentEditorApi)
        if (!range) return []
        const markerPresent = boundText.includes(thread.marker)
        const classNames = ['refmd-comment-highlight']
        if (thread.resolvedAt) {
          classNames.push('refmd-comment-highlight-resolved')
        }
        if (!thread.anchored || !markerPresent) {
          classNames.push('refmd-comment-highlight-unlinked')
        }
        if (activeCommentThreadId === thread.id) {
          classNames.push('refmd-comment-highlight-active')
        }
        const markerRange = findCommentMarkerRange(thread, boundText, documentEditorApi)
        const threadDecorations: DocumentEditorDecorationInput[] = [
          {
            range,
            inlineClassName: classNames.join(' '),
            overviewRulerColor: thread.resolvedAt ? '#94a3b8' : '#8b5cf6',
            minimapColor: thread.resolvedAt ? '#94a3b8' : '#8b5cf6',
          },
        ]
        if (markerRange) {
          threadDecorations.push({
            range: markerRange,
            inlineClassName: 'refmd-comment-anchor-hidden',
          })
        }
        return threadDecorations
      })

    return documentEditorApi.setDecorations('core-comments', decorations)
  }, [activeCommentThreadId, boundText, commentThreads, documentEditorApi])

  useEffect(() => {
    if (!documentEditorApi) return
    const editor = editorRef.current as RefmdEditorInstance | null
    const monacoInstance = editor?.__monaco
    const model = editor?.getModel()
    if (!editor || !monacoInstance || !model) return

    const widgets: monacoNs.editor.IContentWidget[] = []
    const disposables: Array<{ dispose: () => void }> = []

    const groups = new Map<
      number,
      Array<{
        thread: (typeof commentThreads)[number]
        range: DocumentEditorRange
        markerPresent: boolean
      }>
    >()

    commentThreads.forEach((thread) => {
      const range = findCommentThreadRange(thread, boundText, documentEditorApi)
      if (!range) return

      const lineNumber = Math.max(
        1,
        Math.min(model.getLineCount(), Math.floor(range.startLineNumber)),
      )
      const items = groups.get(lineNumber) ?? []
      items.push({
        thread,
        range,
        markerPresent: boundText.includes(thread.marker),
      })
      groups.set(lineNumber, items)
    })

    groups.forEach((items, lineNumber) => {
      const sortedItems = [...items].sort((a, b) => {
        if (a.range.startColumn !== b.range.startColumn) {
          return a.range.startColumn - b.range.startColumn
        }
        return a.thread.createdAt.localeCompare(b.thread.createdAt)
      })
      const activeIndex = sortedItems.findIndex(
        ({ thread }) => thread.id === activeCommentThreadId,
      )
      const activeItem = activeIndex >= 0 ? sortedItems[activeIndex] : null
      const hasResolvedOnly = sortedItems.every(({ thread }) => thread.resolvedAt)
      const hasUnlinked = sortedItems.some(
        ({ thread, markerPresent }) => !thread.anchored || !markerPresent,
      )
      const title =
        sortedItems.length > 1
          ? `${sortedItems.length} comments`
          : sortedItems[0].thread.resolvedAt
            ? 'Resolved comment'
            : 'Comment'
      const node = document.createElement('button')
      node.type = 'button'
      node.className = [
        'refmd-comment-widget',
        sortedItems.length > 1 ? 'refmd-comment-widget-grouped' : '',
        hasResolvedOnly ? 'refmd-comment-widget-resolved' : '',
        hasUnlinked ? 'refmd-comment-widget-unlinked' : '',
        activeItem ? 'refmd-comment-widget-active' : '',
      ]
        .filter(Boolean)
        .join(' ')
      node.title = title
      node.setAttribute('aria-label', node.title)
      if (sortedItems.length > 1) {
        node.textContent = String(sortedItems.length)
      }
      node.addEventListener('mousedown', (event) => {
        event.preventDefault()
        event.stopPropagation()
      })
      node.addEventListener('click', (event) => {
        event.preventDefault()
        event.stopPropagation()
        const nextIndex =
          activeIndex >= 0 ? (activeIndex + 1) % sortedItems.length : 0
        handleSelectCommentThread(sortedItems[nextIndex].thread.id)
      })

      const widget: monacoNs.editor.IContentWidget = {
        getId: () => `core-comment-widget-${lineNumber}`,
        getDomNode: () => node,
        getPosition: () => ({
          position: {
            lineNumber,
            column: 1,
          },
          preference: [
            monacoInstance.editor.ContentWidgetPositionPreference.EXACT,
          ],
        }),
      }

      editor.addContentWidget(widget)
      editor.layoutContentWidget(widget)
      widgets.push(widget)
    })

    const layoutWidgets = () => {
      widgets.forEach((widget) => {
        try {
          editor.layoutContentWidget(widget)
        } catch {
          /* noop */
        }
      })
    }
    try {
      disposables.push(editor.onDidScrollChange(layoutWidgets))
      disposables.push(editor.onDidLayoutChange(layoutWidgets))
    } catch {
      /* noop */
    }

    return () => {
      disposables.forEach((disposable) => {
        try {
          disposable.dispose()
        } catch {
          /* noop */
        }
      })
      widgets.forEach((widget) => {
        try {
          editor.removeContentWidget(widget)
        } catch {
          /* noop */
        }
      })
    }
  }, [
    activeCommentThreadId,
    boundText,
    commentThreads,
    documentEditorApi,
    editorMountNonce,
    editorRef,
    handleSelectCommentThread,
  ])

  useEffect(() => {
    if (!documentEditorApi) return
    return documentEditorApi.onGlyphMarginClick((lineNumber) => {
      const candidates = commentThreads
        .map((thread) => {
          const range = findCommentThreadRange(thread, boundText, documentEditorApi)
          if (!range) return null
          const glyphLineNumber = Math.max(1, Math.floor(range.startLineNumber))
          if (lineNumber !== glyphLineNumber) {
            return null
          }
          return { thread, range }
        })
        .filter((item): item is NonNullable<typeof item> => Boolean(item))
        .sort((a, b) => {
          if (a.range.startColumn !== b.range.startColumn) {
            return a.range.startColumn - b.range.startColumn
          }
          return a.thread.createdAt.localeCompare(b.thread.createdAt)
        })
      if (!candidates.length) return
      const activeIndex = candidates.findIndex(
        ({ thread }) => thread.id === activeCommentThreadId,
      )
      const nextIndex =
        activeIndex >= 0 ? (activeIndex + 1) % candidates.length : 0
      handleSelectCommentThread(candidates[nextIndex].thread.id)
    })
  }, [
    activeCommentThreadId,
    boundText,
    commentThreads,
    documentEditorApi,
    handleSelectCommentThread,
  ])

  const documentEditorDocument = useMemo<DocumentEditorDocumentApi>(() => {
    const ytext = doc.getText('content')
    return {
      id: documentId,
      type: documentType ?? 'markdown',
      title: documentTitle ?? null,
      token: shareToken ?? null,
      readOnly,
      getContent: () => ytext.toString(),
      setContent: (value) => {
        if (readOnly) {
          emitReadOnlyWarning()
          return false
        }
        const next = String(value ?? '')
        doc.transact(() => {
          ytext.delete(0, ytext.length)
          ytext.insert(0, next)
        })
        markDocumentContentDirty(documentId, next)
        return true
      },
      onContentChange: (callback) => {
        const observer = () => callback(ytext.toString())
        ytext.observe(observer)
        return () => {
          try {
            ytext.unobserve(observer)
          } catch {
            /* noop */
          }
        }
      },
    }
  }, [doc, documentId, documentTitle, documentType, emitReadOnlyWarning, readOnly, shareToken])

  const pluginPanes = useDocumentEditorPlugins({
    enabled: documentEditorPluginsEnabled && !conflictView,
    document: documentEditorDocument,
    editor: documentEditorApi,
    onPaneHostChange: onDocumentEditorPaneHostChange,
  })

  const handleCommentsRequestEditor = useCallback(() => {
    if (isMobile) {
      onCommentsOpenChange?.(false)
      safeExecute('show editor for comments', () => setViewMode('editor'))
      return
    }
    safeExecute('show split view for comments', () => setViewMode('split'))
  }, [isMobile, onCommentsOpenChange, setViewMode])

  const commentsPanel = commentsOpen ? (
    <CommentsPanel
      documentId={documentId}
      token={shareToken}
      content={boundText}
      editor={documentEditorApi}
      readOnly={readOnly}
      userName={userName ?? null}
      composerState={commentComposerState}
      onComposerStateChange={setCommentComposerState}
      activeThreadId={activeCommentThreadId}
      onClose={() => onCommentsOpenChange?.(false)}
      onRequestEditor={handleCommentsRequestEditor}
      onActiveThreadChange={handleSelectCommentThread}
    />
  ) : undefined

  const resolvedExtraRight = extraRight ?? commentsPanel ?? pluginPanes.extraRight

  

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
        extraRight={resolvedExtraRight}
        keepEditorMounted={isMobile && Boolean(commentsPanel)}
        embedded={embedded}
        toolbar={Toolbar}
        toolbarOpen={toolbarOpen}
        onToolbarOpenChange={setToolbarOpen}
        monacoTheme={monacoTheme}
        onEditorBeforeMount={handleBeforeMount}
        readOnly={readOnly}
        onEditorDropFiles={handleEditorDropFiles}
        onEditorMount={handleEditorMount}
        onEditorUnmount={handleEditorUnmount}
        editorRef={editorRef}
        syncScroll={syncScroll}
        onPreviewScroll={handlePreviewScroll}
        previewScrollPct={previewScrollPct}
        previewAnchorLine={previewAnchorLine}
        lockActive={lockActive}
        onPreviewNavigate={onPreviewNavigate}
        documentId={documentId}
        onToggleTask={handleTaskToggle}
        previewContentOverride={
          previewOverride === undefined ? undefined : renderedPreviewContent
        }
        content={renderedPreviewContent}
        vimStatusBarRef={vimStatusBarRef}
        showVimStatusBar={isVimMode}
        uploadStatus={uploadStatus}
        renderPreview={renderPreview}
        commentMarkers={previewCommentMarkers}
        activeCommentThreadId={activeCommentThreadId}
        onCommentMarkerSelect={handleSelectCommentThread}
        conflictControls={conflictControls}
        conflictBadgeText={conflictBadgeText}
        conflictHunkWidgets={conflictHunkWidgets}
        conflictView={
          conflictView
            ? {
                ...conflictView,
                theme: monacoTheme,
              }
            : undefined
        }
      />

      <CursorDisplay awareness={awareness} className={embedded ? 'top-12' : undefined} />
    </div>
  )
}

export default MarkdownEditor
