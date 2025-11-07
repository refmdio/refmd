import type { OnMount } from '@monaco-editor/react'
import { useNavigate } from '@tanstack/react-router'
import type * as monacoNs from 'monaco-editor'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import type { Awareness } from 'y-protocols/awareness'
import * as Y from 'yjs'


import { useTheme } from '@/shared/contexts/theme-context'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { useShortcut } from '@/shared/hooks/use-shortcut'
import type { ViewMode } from '@/shared/types/view-mode'

import { listDocuments } from '@/entities/document'

import { useAwarenessStyles } from '@/features/edit-document/hooks/useAwarenessStyles'
import { useEditorUploads } from '@/features/edit-document/hooks/useEditorUploads'
import { useMarkdownCommands, type MarkdownCommand } from '@/features/edit-document/hooks/useMarkdownCommands'
import { useMonacoBinding } from '@/features/edit-document/hooks/useMonacoBinding'
import { useScrollSync } from '@/features/edit-document/hooks/useScrollSync'
import { registerWikiLinkCompletion } from '@/features/edit-document/lib/monaco/wiki-link-provider'
import { useEditorContext } from '@/features/edit-document/model/editor-context'
import { useViewContext } from '@/features/edit-document/model/view-context'

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

import { loadMonacoVim } from '../lib/monaco/vim-loader'

import CursorDisplay from './CursorDisplay'
import EditorLayout from './EditorLayout'
import EditorToolbar from './Toolbar'

export type MarkdownEditorProps = {
  doc: Y.Doc
  awareness: Awareness
  connected: boolean
  initialView?: ViewMode
  userName?: string
  userId?: string
  documentId: string
  readOnly?: boolean
  extraRight?: React.ReactNode
}


export function MarkdownEditor(props: MarkdownEditorProps) {
  const { doc, awareness, initialView: initialViewProp = 'split', userId, userName, documentId, readOnly = false, extraRight } = props
  const { isDarkMode } = useTheme()
  const isMobile = useIsMobile()
  const { setEditor } = useEditorContext()
  const { viewMode, setViewMode } = useViewContext()
  const navigate = useNavigate()
  const monacoTheme = isDarkMode ? 'vs-dark' : 'vs'
  const view = viewMode
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
  useEffect(() => { syncScrollRef.current = syncScroll }, [syncScroll])
  const vimModeRef = useRef<{ dispose: () => void } | null>(null)
  const vimStatusBarRef = useRef<HTMLDivElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const viewRef = useRef<ViewMode>(initialViewProp)
  useEffect(() => {
    viewRef.current = viewMode
  }, [viewMode])
  const { onMount: onMonacoMount, text: boundText, editorRef } = useMonacoBinding({
    doc,
    awareness,
    language: 'markdown',
    onTextChange: () => {},
  })
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
    safeExecute('set initial view mode', () => setViewMode(initialViewProp))
  }, [initialViewProp, setViewMode])

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
  }, [doc, readOnly, emitReadOnlyWarning])

  const handleMount: OnMount = useCallback((editor, monaco) => {
    // First, bind Monaco to Yjs via hook
    onMonacoMount(editor, monaco)
    ;(editor as any).__monaco = monaco
    setReadOnlyOverlay(editor as any, monaco as any, readOnly)
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
  }, [onMonacoMount, isVimMode, syncScroll, handleEditorScroll, emitReadOnlyWarning, readOnly, setReadOnlyOverlay, enableVimMode])

  useEffect(() => {
    const editorInstance = editorRef.current as (monacoNs.editor.IStandaloneCodeEditor & { __readOnlyOverlay?: { widget: monacoNs.editor.IOverlayWidget; domNode: HTMLElement }; __monaco?: typeof monacoNs }) | null
    if (!editorInstance) return
    const monacoInstance = editorInstance.__monaco
    setReadOnlyOverlay(editorInstance, monacoInstance, readOnly)
  }, [readOnly, setReadOnlyOverlay])

  useEffect(() => () => {
    const anyEditor = editorRef.current as (monacoNs.editor.IStandaloneCodeEditor & { __readOnlyOverlay?: { widget: monacoNs.editor.IOverlayWidget; domNode: HTMLElement }; __monaco?: typeof monacoNs }) | undefined
    safeExecute('dispose change listener', () => (anyEditor as any)?.__disposeChange?.())
    safeExecute('dispose scroll listener', () => (anyEditor as any)?.__disposeScroll?.())
    safeExecute('dispose paste handler', () => (anyEditor as any)?.__disposePaste?.())
    safeExecute('dispose wiki handler', () => (anyEditor as any)?.__disposeWiki?.())
    safeExecute('dispose cursor handler', () => (anyEditor as any)?.__disposeCursor?.())
    safeExecute('dispose monaco markdown handler', () => (anyEditor as any)?.__disposeMonacoMd?.())
    safeExecute('dispose keydown handler', () => (anyEditor as any)?.__disposeKeydown?.())
    safeExecute('dispose read-only overlay', () => {
      if (anyEditor?.__readOnlyOverlay) {
        try { anyEditor.removeOverlayWidget(anyEditor.__readOnlyOverlay.widget) } catch {}
        try { anyEditor.__readOnlyOverlay.domNode.remove() } catch {}
        delete anyEditor.__readOnlyOverlay
      }
      if (anyEditor && '__monaco' in anyEditor) {
        delete (anyEditor as any).__monaco
      }
    })
    disableVimMode()
    setEditor(null)
  }, [editorRef, setEditor, disableVimMode])

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
    if (fileInputRef.current) fileInputRef.current.click()
  }, [emitReadOnlyWarning, readOnly])

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
    setSyncScroll((value) => !value)
  }, [])
  const shortcutToggleVim = useCallback(() => {
    void toggleVim()
  }, [toggleVim])

  useShortcut('editor.sync-scroll.toggle', shortcutToggleSync)
  useShortcut('editor.vim.toggle', shortcutToggleVim)
  useShortcut('editor.upload.trigger', handleFileUpload)

  const onPreviewNavigate = useCallback(async (target: string) => {
    const uuidRe = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
    let id = target
    if (!uuidRe.test(target)) {
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
        navigate({ to: '/document/$id', params: { id } })
      } catch (error) {
        logEditorError('navigate to document from preview', error)
        window.location.href = `/document/${id}`
      }
    }
  }, [navigate])

  // Ensure Monaco relayouts when view/layout changes or container resizes
  useEffect(() => {
    const ed = editorRef.current as monacoNs.editor.IStandaloneCodeEditor | null
    if (!ed) return
    const relayout = () => safeExecute('editor relayout', () => ed.layout())
    // immediate relayout on view change
    relayout()
    // also schedule once after transition
    const t = setTimeout(relayout, 120)
    // observe parent size changes
    let ro: ResizeObserver | null = null
    try {
      const node = ed.getDomNode() as HTMLElement | null
      const parent = node?.parentElement || node
      if (parent && 'ResizeObserver' in window) {
        ro = new ResizeObserver(() => relayout())
        ro.observe(parent)
      }
    } catch (error) {
      logEditorError('init resize observer', error)
    }
    // window resize
    window.addEventListener('resize', relayout)
    return () => {
      clearTimeout(t)
      safeExecute('disconnect resize observer', () => {
        if (ro) ro.disconnect()
      })
      window.removeEventListener('resize', relayout)
    }
  }, [view, editorRef])

  const handleEditorMount = useCallback(
    (editor: monacoNs.editor.IStandaloneCodeEditor, monaco: Parameters<OnMount>[1]) => {
      setEditor(editor as any)
      handleMount(editor, monaco)
    },
    [handleMount, setEditor],
  )

  const handleEditorDropFiles = useCallback(
    async (files: File[]) => {
      await uploadFiles(files)
    },
    [uploadFiles],
  )

  

  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={async (e) => {
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
        toolbar={Toolbar}
        toolbarOpen={toolbarOpen}
        onToolbarOpenChange={setToolbarOpen}
        monacoTheme={monacoTheme}
        readOnly={readOnly}
        onEditorDropFiles={handleEditorDropFiles}
        onEditorMount={handleEditorMount}
        editorRef={editorRef}
        syncScroll={syncScroll}
        onPreviewScroll={handlePreviewScroll}
        previewScrollPct={previewScrollPct}
        previewAnchorLine={previewAnchorLine}
        lockActive={lockActive}
        onPreviewNavigate={onPreviewNavigate}
        documentId={documentId}
        onToggleTask={handleTaskToggle}
        content={boundText}
        vimStatusBarRef={vimStatusBarRef}
        showVimStatusBar={isVimMode}
        uploadStatus={uploadStatus}
      />

      <CursorDisplay awareness={awareness} />
    </div>
  )
}

export default MarkdownEditor
