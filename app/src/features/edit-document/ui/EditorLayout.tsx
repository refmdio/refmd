import { DiffEditor } from '@monaco-editor/react'
import { AlertTriangle, Check, Loader2, SlidersHorizontal, X } from 'lucide-react'
import type * as monacoNs from 'monaco-editor'
import { useCallback, useMemo, useEffect, useRef, useState, type CSSProperties, type ReactNode, type MutableRefObject } from 'react'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import type { ViewMode } from '@/shared/types/view-mode'
import { Button } from '@/shared/ui/button'

import type { UploadStatus } from '@/features/edit-document/hooks/useEditorUploads'
import { ensureRefmdThemes } from '@/features/edit-document/lib/monaco/theme'

import EditorPane from './EditorPane'
import PreviewPane, { type PreviewPaneProps } from './PreviewPane'

export type EditorLayoutProps = {
  isMobile: boolean
  view: ViewMode
  extraRight?: ReactNode
  toolbar: ReactNode
  toolbarOpen: boolean
  onToolbarOpenChange: (open: boolean) => void
  monacoTheme: string
  onEditorBeforeMount?: (monaco: typeof import('monaco-editor')) => void
  readOnly: boolean
  onEditorDropFiles: (files: File[]) => Promise<void>
  onEditorMount: (editor: monacoNs.editor.IStandaloneCodeEditor, monaco: typeof import('monaco-editor')) => void
  editorRef: MutableRefObject<monacoNs.editor.IStandaloneCodeEditor | null>
  syncScroll: boolean
  onPreviewScroll: (percentage: number) => void
  previewScrollPct?: number
  previewAnchorLine?: number
  lockActive: boolean
  onPreviewNavigate: (target: string) => void | Promise<void>
  documentId: string
  onToggleTask?: (lineNumber: number, checked: boolean) => void
  content: string
  vimStatusBarRef: MutableRefObject<HTMLDivElement | null>
  showVimStatusBar: boolean
  uploadStatus: UploadStatus
  renderPreview?: (props: PreviewPaneProps) => ReactNode
  editorOverlay?: ReactNode
  editorBanner?: ReactNode
  conflictControls?: ReactNode
  conflictHunkWidgets?: Array<{
    id: string
    line: number
    choice?: 'ours' | 'theirs'
    onChoose: (side: 'ours' | 'theirs') => void
  }>
  conflictView?: {
    kind: 'text' | 'binary'
    original?: string
    modified?: string
    onChange?: (val: string) => void
    readOnly?: boolean
    theme?: string
    actions?: {
      onKeepMine?: () => void
      onTakeTheirs?: () => void
      onApplyMerged?: () => void
    }
  }
}

export function EditorLayout({
  isMobile,
  view,
  extraRight,
  toolbar,
  toolbarOpen,
  onToolbarOpenChange,
  monacoTheme,
  onEditorBeforeMount,
  readOnly,
  onEditorDropFiles,
  onEditorMount,
  editorRef,
  syncScroll,
  onPreviewScroll,
  previewScrollPct,
  previewAnchorLine,
  lockActive,
  onPreviewNavigate,
  documentId,
  onToggleTask,
  content,
  vimStatusBarRef,
  showVimStatusBar,
  uploadStatus,
  renderPreview,
  editorOverlay,
  editorBanner,
  conflictControls,
  conflictHunkWidgets,
  conflictView,
}: EditorLayoutProps) {
  const diffEditorRef = useRef<monacoNs.editor.IStandaloneDiffEditor | null>(null)
  const monacoRef = useRef<typeof import('monaco-editor') | null>(null)
  const [diffReady, setDiffReady] = useState(false)
  const overlayNodesRef = useRef<Record<string, HTMLDivElement>>({})
  const overlayDisposablesRef = useRef<monacoNs.IDisposable[]>([])

  useEffect(() => {
    // cleanup helper
    const cleanup = () => {
      Object.values(overlayNodesRef.current).forEach((node) => node.remove())
      overlayNodesRef.current = {}
      overlayDisposablesRef.current.forEach((d) => d.dispose())
      overlayDisposablesRef.current = []
    }

    const diff = diffEditorRef.current
    const monacoInstance = monacoRef.current
    if (!diff || !monacoInstance || !diffReady) {
      cleanup()
      return
    }
    const modified = diff.getModifiedEditor()
    const model = modified?.getModel()
    if (!modified || !model || !conflictHunkWidgets || conflictHunkWidgets.length === 0) {
      cleanup()
      return
    }

    const host =
      modified.getDomNode()?.querySelector('.overflow-guard') ??
      modified.getDomNode() ??
      document.createElement('div')
    if (!host) {
      cleanup()
      return
    }
    if (host instanceof HTMLElement) {
      const style = host.style
      if (!style.position || style.position === 'static') {
        style.position = 'relative'
      }
    }

    const isDark = typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
    const palette = {
      ours: {
        bg: isDark ? 'rgba(127,29,29,0.30)' : '#fef2f2',
        bgActive: isDark ? 'rgba(185,28,28,0.55)' : '#fee2e2',
        color: isDark ? '#fecdd3' : '#b91c1c',
      },
      theirs: {
        bg: isDark ? 'rgba(5,46,22,0.30)' : '#f0fdf4',
        bgActive: isDark ? 'rgba(34,197,94,0.50)' : '#dcfce7',
        color: isDark ? '#bbf7d0' : '#166534',
      },
    }

    const createNode = (hunk: typeof conflictHunkWidgets[number]) => {
      const node = document.createElement('div')
      node.style.position = 'absolute'
      node.style.display = 'inline-flex'
      node.style.flexDirection = 'row'
      node.style.alignItems = 'center'
      node.style.gap = '8px'
      node.style.padding = '2px 6px'
      node.style.borderRadius = '10px'
      node.style.background = 'transparent'
      node.style.pointerEvents = 'auto'
      node.style.whiteSpace = 'nowrap'
      node.style.zIndex = '50'

      const makeBtn = (label: string, side: 'ours' | 'theirs') => {
        const btn = document.createElement('button')
        btn.textContent = label
        btn.style.fontSize = '11px'
        btn.style.padding = '4px 10px'
        btn.style.borderRadius = '8px'
        btn.style.border = 'none'
        btn.style.cursor = 'pointer'
        btn.style.lineHeight = '1'
        btn.style.fontWeight = hunk.choice === side ? '700' : '500'
        btn.style.display = 'inline-flex'
        btn.style.alignItems = 'center'
        btn.style.justifyContent = 'center'
        const colors = side === 'ours' ? palette.ours : palette.theirs
        btn.style.background = hunk.choice === side ? colors.bgActive : colors.bg
        btn.style.color = colors.color
        btn.onmousedown = (e) => {
          e.preventDefault()
          e.stopPropagation()
        }
        btn.onclick = (e) => {
          e.preventDefault()
          e.stopPropagation()
          hunk.onChoose(side)
        }
        return btn
      }

      node.appendChild(makeBtn('Keep Mine', 'ours'))
      node.appendChild(makeBtn('Take Remote', 'theirs'))
      return node
    }

    conflictHunkWidgets.forEach((hunk) => {
      const node = createNode(hunk)
      overlayNodesRef.current[hunk.id] = node
      host.appendChild(node)
    })

    const updatePositions = () => {
      const layout = modified.getLayoutInfo()
      const lineHeight = modified.getOption(monacoInstance.editor.EditorOption.lineHeight)
      const rightInset =
        (layout.minimap?.renderMinimap ? layout.minimap.minimapWidth : 0) +
        layout.verticalScrollbarWidth +
        layout.glyphMarginWidth +
        12
      conflictHunkWidgets.forEach((hunk) => {
        const node = overlayNodesRef.current[hunk.id]
        if (!node) return
        const top = modified.getTopForLineNumber(Math.max(hunk.line, 1)) + lineHeight - 2
        node.style.top = `${top}px`
        node.style.right = `${rightInset}px`
      })
    }

    updatePositions()

    overlayDisposablesRef.current.push(
      modified.onDidScrollChange(() => updatePositions()),
      modified.onDidLayoutChange(() => updatePositions()),
      modified.onDidChangeConfiguration(() => updatePositions()),
    )

    return cleanup
  }, [conflictHunkWidgets, diffReady])

  const uploadStatusNode = (() => {
    if (uploadStatus.state === 'idle') return null
    let primary = ''
    let secondary: string | null = null
    let icon: ReactNode = null

    if (uploadStatus.state === 'uploading') {
      const currentIndex = Math.min(uploadStatus.completed + 1, uploadStatus.total)
      primary = `Uploading ${currentIndex} / ${uploadStatus.total}`
      secondary = uploadStatus.currentFile ?? null
      icon = <Loader2 className="h-4 w-4 shrink-0 text-primary animate-spin" aria-hidden="true" />
    } else if (uploadStatus.state === 'success') {
      const label = uploadStatus.total === 1 ? 'file' : 'files'
      primary = `Uploaded ${uploadStatus.completed} ${label}`
      icon = <Check className="h-4 w-4 shrink-0 text-emerald-500" aria-hidden="true" />
    } else {
      const failedLabel = uploadStatus.failed === 1 ? 'file' : 'files'
      primary = 'Upload incomplete'
      secondary = `${uploadStatus.completed} of ${uploadStatus.total} files succeeded (${uploadStatus.failed} ${failedLabel} failed)`
      icon = <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />
    }

    return (
      <div
        className="pointer-events-auto flex max-w-xs items-start gap-2 rounded-lg border border-border/60 bg-background/95 px-3 py-2 text-xs shadow-lg backdrop-blur-sm"
        aria-live="polite"
      >
        {icon}
        <div className="flex min-w-0 flex-col gap-1">
          <span className="font-medium text-foreground">{primary}</span>
          {secondary ? <span className="text-[11px] text-muted-foreground truncate">{secondary}</span> : null}
        </div>
      </div>
    )
  })()

  const layoutState = useMemo(() => {
    let wEditor = '0%'
    let wPreview = '0%'
    let wExtra = '0%'

    if (view === 'editor') {
      wEditor = '100%'
    } else if (view === 'preview') {
      wPreview = '100%'
    } else if (view === 'split') {
      if (extraRight) {
        wEditor = '33.33%'
        wPreview = '33.33%'
        wExtra = '33.34%'
      } else {
        wEditor = '50%'
        wPreview = '50%'
      }
    }

    const isDesktopSingleEditor = !isMobile && view === 'editor' && !extraRight
    const isDesktopSinglePreview = !isMobile && view === 'preview' && !extraRight

    if (!isMobile && extraRight) {
      if (view === 'preview') {
        wPreview = '50%'
        wExtra = '50%'
      } else if (view === 'editor') {
        wEditor = '50%'
        wExtra = '50%'
      }
    }

    const shouldForceFloatingToc = !isMobile && view === 'preview' && !!extraRight

    return {
      wEditor,
      wPreview,
      wExtra,
      isDesktopSingleEditor,
      isDesktopSinglePreview,
      shouldForceFloatingToc,
    }
  }, [view, extraRight, isMobile])

  const handleToolbarClose = useCallback(() => onToolbarOpenChange(false), [onToolbarOpenChange])
  const handleToolbarOpen = useCallback(() => onToolbarOpenChange(true), [onToolbarOpenChange])

  const revealEditorLine = useCallback(
    (line: number) => {
      const editor = editorRef.current
      if (!editor) return
      try {
        ;(editor as any).revealLineNearTop?.(line)
      } catch {}
    },
    [editorRef],
  )

  const handlePreviewScroll = useCallback(
    (pct: number) => {
      if (!syncScroll || view !== 'split') return
      onPreviewScroll(pct)
    },
    [onPreviewScroll, syncScroll, view],
  )

  return (
    <div
      className={cn(
        'flex flex-1 min-w-0 overflow-hidden',
        isMobile ? 'flex-col min-h-0' : 'gap-6',
      )}
    >
      {layoutState.wEditor !== '0%' && (
        <div
          className={cn(
            'relative flex flex-1 min-w-0 flex-col overflow-hidden',
            !isMobile &&
              'rounded-3xl border border-border/40 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80',
            layoutState.isDesktopSingleEditor && 'mx-auto w-full max-w-6xl',
          )}
          style={
            isMobile
              ? undefined
              : ({ width: layoutState.wEditor, transition: 'width 80ms ease' } as CSSProperties)
          }
        >
          <div
            className={cn(
                'flex flex-1 min-h-0 flex-col',
                !isMobile && 'px-4 pb-6 pt-6 sm:px-6 sm:pb-8 sm:pt-8',
              )}
            >
              {editorBanner ? <div className="mb-3">{editorBanner}</div> : null}
            <div className="relative flex flex-1 min-h-0">
              {editorOverlay ? (
                <div className="pointer-events-auto absolute left-3 right-3 top-3 z-40">
                  {editorOverlay}
                </div>
              ) : null}
              <div className="pointer-events-none absolute bottom-6 right-6 z-40 flex flex-col items-end gap-3">
                {uploadStatusNode}
                {toolbarOpen ? (
                  <div className={`${overlayPanelClass} pointer-events-auto flex items-start gap-2 px-3 py-3`}>
                    <div className="max-h-[60vh] overflow-y-auto pr-1">{toolbar}</div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={handleToolbarClose}
                      className="mt-1 h-8 w-8 rounded-full text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground"
                      title="Hide editor tools"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <div className="pointer-events-auto">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={handleToolbarOpen}
                      className="p-3 rounded-full border border-primary/60 bg-primary text-primary-foreground shadow-lg transition-all hover:bg-primary/90 hover:shadow-xl"
                      title="Show editor tools"
                    >
                      <SlidersHorizontal className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </div>
              <div className="flex flex-1 min-h-0">
                {conflictView && conflictView.kind === 'text' ? (
                  <div className="conflict-diff flex-1 overflow-hidden">
                    <div className="h-full">
                      <DiffEditor
                        original={conflictView.original ?? ''}
                        modified={conflictView.modified ?? ''}
                        beforeMount={(monacoInstance) => {
                          monacoRef.current = monacoInstance
                          ensureRefmdThemes(monacoInstance)
                        }}
                        onMount={(editor, monacoInstance) => {
                          diffEditorRef.current = editor
                          monacoRef.current = monacoInstance
                          setDiffReady(true)
                          monacoInstance.editor.setTheme(conflictView.theme ?? monacoTheme)
                          const modified = editor.getModifiedEditor()
                          const original = editor.getOriginalEditor()
                          // Align gutters; show line numbers only on original
                          original.updateOptions({
                            glyphMargin: false,
                            lineDecorationsWidth: 24,
                            lineNumbersMinChars: 1, // Monaco enforces >=1
                            lineNumbers: 'on' as const,
                          })
                          modified.updateOptions({
                            glyphMargin: false,
                            lineDecorationsWidth: 24,
                            lineNumbersMinChars: 1, // Monaco enforces >=1
                            lineNumbers: 'off' as const,
                          })
                          if (conflictView.onChange) {
                            modified.onDidChangeModelContent(() => {
                              conflictView.onChange?.(modified.getValue())
                            })
                          }
                        }}
                        language="markdown"
                        theme={conflictView.theme ?? monacoTheme}
                        options={{
                          readOnly: conflictView.readOnly,
                          renderSideBySide: false,
                          renderMarginRevertIcon: false,
                          renderOverviewRuler: false,
                          renderIndicators: false,
                          minimap: { enabled: false },
                          automaticLayout: true,
                          wordWrap: 'on',
                          scrollBeyondLastLine: true,
                          fontSize: isMobile ? 17 : 14,
                          lineHeight: isMobile ? 26 : 22,
                        }}
                      />
                    </div>
                    {conflictControls ? <div className="mt-3 px-1">{conflictControls}</div> : null}
                  </div>
                ) : conflictView && conflictView.kind === 'binary' ? (
                  <div className="flex flex-1 items-center justify-center rounded-2xl border border-border/50 bg-muted/30 px-4 py-6 text-sm text-muted-foreground">
                    Binary conflict. Choose a side to continue.
                  </div>
                ) : (
                  <EditorPane
                    theme={monacoTheme}
                    onBeforeMount={onEditorBeforeMount}
                    readOnly={readOnly}
                    onDropFiles={async (files) => {
                      if (!readOnly) await onEditorDropFiles(files)
                    }}
                    isMobile={isMobile}
                    onMount={onEditorMount}
                    vimStatusBarRef={vimStatusBarRef}
                    showVimStatusBar={showVimStatusBar}
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {layoutState.wPreview !== '0%' && (
        <div
          className={cn(
            'relative flex flex-1 min-w-0 flex-col overflow-hidden',
            !isMobile &&
              'rounded-3xl border border-border/40 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80',
            layoutState.isDesktopSinglePreview && 'mx-auto w-full max-w-6xl',
          )}
          style={
            isMobile
              ? undefined
              : ({ width: layoutState.wPreview, transition: 'width 80ms ease' } as CSSProperties)
          }
        >
          <div
            className={cn(
              'flex flex-1 min-h-0 flex-col',
              !isMobile && 'px-4 pb-6 pt-6 sm:px-6 sm:pb-8 sm:pt-8',
            )}
          >
            {(() => {
              const previewProps: PreviewPaneProps = {
                content,
                forceFloatingToc: layoutState.shouldForceFloatingToc,
                viewMode: view === 'split' ? 'split' : 'preview',
                onNavigate: onPreviewNavigate,
                onScroll: (_top, pct) => handlePreviewScroll(pct),
                onScrollAnchorLine: (line) => {
                  if (!syncScroll || view !== 'split') return
                  revealEditorLine(line)
                },
                scrollPercentage: syncScroll && view === 'split' ? previewScrollPct : undefined,
                scrollToLine: syncScroll && view === 'split' ? previewAnchorLine : undefined,
                stickToBottom: syncScroll ? lockActive : false,
                documentIdOverride: documentId,
                onToggleTask: readOnly ? undefined : onToggleTask,
                taskToggleDisabled: readOnly,
              }

              return renderPreview ? renderPreview(previewProps) : <PreviewPane {...previewProps} />
            })()}
          </div>
        </div>
      )}

      {layoutState.wExtra !== '0%' && (
        <div
          className={cn(
            'relative flex flex-1 min-w-0 flex-col overflow-hidden',
            !isMobile &&
              'rounded-3xl border border-border/40 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80',
          )}
          style={
            isMobile
              ? undefined
              : ({ width: layoutState.wExtra, transition: 'width 80ms ease' } as CSSProperties)
          }
        >
          <div
            className={cn(
              'flex flex-1 min-h-0 flex-col',
              !isMobile && 'px-4 pb-6 pt-6 sm:px-6 sm:pb-8 sm:pt-8',
            )}
          >
            {extraRight}
          </div>
        </div>
      )}
    </div>
  )
}

export default EditorLayout
