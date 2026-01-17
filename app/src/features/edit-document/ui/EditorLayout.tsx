import { MergeView } from '@codemirror/merge'
import { Extension } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { AlertTriangle, Check, Loader2, SlidersHorizontal, X } from 'lucide-react'
import { useCallback, useMemo, useEffect, useRef, type CSSProperties, type ReactNode, type MutableRefObject } from 'react'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import type { ViewMode } from '@/shared/types/view-mode'
import { Button } from '@/shared/ui/button'

import type { UploadStatus } from '@/features/edit-document/hooks/useEditorUploads'
import { createBaseExtensions } from '@/features/edit-document/lib/editor'

import EditorPane from './EditorPane'
import PreviewPane, { type PreviewPaneProps } from './PreviewPane'

export type EditorLayoutProps = {
  isMobile: boolean
  view: ViewMode
  extraRight?: ReactNode
  embedded?: boolean
  toolbar: ReactNode
  toolbarOpen: boolean
  onToolbarOpenChange: (open: boolean) => void
  isDarkMode: boolean
  readOnly: boolean
  onEditorDropFiles: (files: File[]) => Promise<void>
  onEditorViewCreated: (view: EditorView) => void
  editorExtensions?: Extension[]
  getInitialContent?: () => string
  editorRef: MutableRefObject<EditorView | null>
  syncScroll: boolean
  onPreviewScroll: (percentage: number) => void
  previewScrollPct?: number
  previewAnchorLine?: number
  lockActive: boolean
  onPreviewNavigate: (target: string) => void | Promise<void>
  documentId: string
  onToggleTask?: (lineNumber: number, checked: boolean) => void
  content: string
  previewContentOverride?: string
  vimStatusBarRef: MutableRefObject<HTMLDivElement | null>
  showVimStatusBar: boolean
  uploadStatus: UploadStatus
  renderPreview?: (props: PreviewPaneProps) => ReactNode
  editorOverlay?: ReactNode
  editorBanner?: ReactNode
  conflictControls?: ReactNode
  conflictBadgeText?: string
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
  embedded = false,
  toolbar,
  toolbarOpen,
  onToolbarOpenChange,
  isDarkMode,
  readOnly,
  onEditorDropFiles,
  onEditorViewCreated,
  editorExtensions,
  getInitialContent,
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
  previewContentOverride,
  vimStatusBarRef,
  showVimStatusBar,
  uploadStatus,
  renderPreview,
  editorOverlay,
  editorBanner,
  conflictControls,
  conflictBadgeText,
  conflictHunkWidgets,
  conflictView,
}: EditorLayoutProps) {
  const mergeViewContainerRef = useRef<HTMLDivElement | null>(null)
  const mergeViewRef = useRef<MergeView | null>(null)

  // Create and manage MergeView for conflict resolution
  useEffect(() => {
    if (!conflictView || conflictView.kind !== 'text' || !mergeViewContainerRef.current) {
      if (mergeViewRef.current) {
        mergeViewRef.current.destroy()
        mergeViewRef.current = null
      }
      return
    }

    const container = mergeViewContainerRef.current
    const baseExtensions = createBaseExtensions({
      isDarkMode,
      readOnly: conflictView.readOnly ?? false,
      vimMode: false,
      isMobile,
      lineWrapping: true,
    })

    const mergeView = new MergeView({
      a: {
        doc: conflictView.original ?? '',
        extensions: [
          ...baseExtensions,
          EditorView.editable.of(false),
        ],
      },
      b: {
        doc: conflictView.modified ?? '',
        extensions: [
          ...baseExtensions,
          EditorView.editable.of(!conflictView.readOnly),
          EditorView.updateListener.of((update) => {
            if (update.docChanged && conflictView.onChange) {
              conflictView.onChange(update.state.doc.toString())
            }
          }),
        ],
      },
      parent: container,
      collapseUnchanged: {},
    })

    mergeViewRef.current = mergeView

    return () => {
      mergeView.destroy()
      mergeViewRef.current = null
    }
  }, [conflictView, isDarkMode, isMobile])

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
      const editorView = editorRef.current
      if (!editorView) return
      try {
        const lineInfo = editorView.state.doc.line(line)
        editorView.dispatch({
          effects: EditorView.scrollIntoView(lineInfo.from, { y: 'start' }),
        })
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
        isMobile ? 'flex-col min-h-0' : embedded ? 'gap-0' : 'gap-6',
      )}
    >
      {layoutState.wEditor !== '0%' && (
        <div
          className={cn(
            'relative flex flex-1 min-w-0 flex-col overflow-hidden',
            !embedded &&
              !isMobile &&
              'rounded-3xl border border-border/40 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80',
            !embedded && layoutState.isDesktopSingleEditor && 'mx-auto w-full max-w-6xl',
          )}
          style={isMobile ? undefined : ({ width: layoutState.wEditor, transition: 'width 80ms ease' } as CSSProperties)}
        >
          <div
            className={cn(
              'flex flex-1 min-h-0 min-w-0 flex-col',
              !isMobile && 'px-4 pb-6 pt-6 sm:px-6 sm:pb-8 sm:pt-8',
            )}
          >
            {editorBanner ? <div className="mb-3">{editorBanner}</div> : null}
            <div className="relative flex flex-1 min-h-0 min-w-0">
              {editorOverlay ? (
                <div className="pointer-events-auto absolute left-3 right-3 top-3 z-40">{editorOverlay}</div>
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
              <div className="flex flex-1 min-h-0 min-w-0">
                {conflictView && conflictView.kind === 'text' ? (
                  <div className="conflict-diff relative flex-1 min-w-0 overflow-hidden">
                    {conflictControls ? <div className="mb-3 px-1">{conflictControls}</div> : null}
                    <div
                      ref={mergeViewContainerRef}
                      className="h-full w-full overflow-auto [&_.cm-editor]:h-full [&_.cm-editor]:outline-none [&_.cm-mergeView]:h-full"
                    />
                    {conflictHunkWidgets && conflictHunkWidgets.length ? (
                      <div className="pointer-events-none absolute bottom-4 left-4 z-10">
                        <div className="inline-flex items-center gap-2 rounded-full bg-background/90 px-3 py-1 text-xs font-semibold text-foreground shadow-lg">
                          <span className="h-2 w-2 rounded-full bg-destructive" aria-hidden />
                          {conflictBadgeText || `${conflictHunkWidgets.length} hunks`}
                        </div>
                      </div>
                    ) : null}
                  </div>
                ) : conflictView && conflictView.kind === 'binary' ? (
                  <div className="flex flex-1 items-center justify-center rounded-2xl border border-border/50 bg-muted/30 px-4 py-6 text-sm text-muted-foreground">
                    Binary conflict. Choose a side to continue.
                  </div>
                ) : (
                  <EditorPane
                    isDarkMode={isDarkMode}
                    readOnly={readOnly}
                    isMobile={isMobile}
                    extensions={editorExtensions}
                    getInitialContent={getInitialContent}
                    onViewCreated={onEditorViewCreated}
                    onDropFiles={async (files) => {
                      if (!readOnly) await onEditorDropFiles(files)
                    }}
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
            !embedded &&
              !isMobile &&
              'rounded-3xl border border-border/40 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80',
            !embedded && layoutState.isDesktopSinglePreview && 'mx-auto w-full max-w-6xl',
          )}
          style={isMobile ? undefined : ({ width: layoutState.wPreview, transition: 'width 80ms ease' } as CSSProperties)}
        >
          <div
            className={cn(
              'flex flex-1 min-h-0 min-w-0 flex-col',
              !isMobile && 'px-4 pb-6 pt-6 sm:px-6 sm:pb-8 sm:pt-8',
            )}
          >
            {(() => {
              const previewProps: PreviewPaneProps = {
                content: previewContentOverride ?? content,
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
            !embedded &&
              !isMobile &&
              'rounded-3xl border border-border/40 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80',
          )}
          style={isMobile ? undefined : ({ width: layoutState.wExtra, transition: 'width 80ms ease' } as CSSProperties)}
        >
          <div
            className={cn(
              'flex flex-1 min-h-0 min-w-0 flex-col',
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
