import { SlidersHorizontal, X } from 'lucide-react'
import type * as monacoNs from 'monaco-editor'
import { useCallback, useMemo, type CSSProperties, type ReactNode } from 'react'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import type { ViewMode } from '@/shared/types/view-mode'
import { Button } from '@/shared/ui/button'

import EditorPane from './EditorPane'
import PreviewPane from './PreviewPane'

export type EditorLayoutProps = {
  isMobile: boolean
  view: ViewMode
  extraRight?: ReactNode
  toolbar: ReactNode
  toolbarOpen: boolean
  onToolbarOpenChange: (open: boolean) => void
  monacoTheme: string
  readOnly: boolean
  onEditorDropFiles: (files: File[]) => Promise<void>
  onEditorMount: (editor: monacoNs.editor.IStandaloneCodeEditor, monaco: typeof import('monaco-editor')) => void
  editorRef: React.MutableRefObject<monacoNs.editor.IStandaloneCodeEditor | null>
  syncScroll: boolean
  onPreviewScroll: (percentage: number) => void
  previewScrollPct?: number
  previewAnchorLine?: number
  lockActive: boolean
  onPreviewNavigate: (target: string) => void | Promise<void>
  documentId: string
  onToggleTask?: (lineNumber: number, checked: boolean) => void
  content: string
}

export function EditorLayout({
  isMobile,
  view,
  extraRight,
  toolbar,
  toolbarOpen,
  onToolbarOpenChange,
  monacoTheme,
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
}: EditorLayoutProps) {
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
            <div className="relative flex flex-1 min-h-0">
              <div className="pointer-events-none absolute bottom-6 right-6 z-40 flex flex-col items-end gap-3">
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
                <EditorPane
                  theme={monacoTheme}
                  readOnly={readOnly}
                  onDropFiles={async (files) => {
                    if (!readOnly) await onEditorDropFiles(files)
                  }}
                  isMobile={isMobile}
                  onMount={onEditorMount}
                />
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
            <PreviewPane
              content={content}
              forceFloatingToc={layoutState.shouldForceFloatingToc}
              viewMode={view === 'split' ? 'split' : 'preview'}
              onNavigate={onPreviewNavigate}
              onScroll={(_top, pct) => handlePreviewScroll(pct)}
              onScrollAnchorLine={(line) => {
                if (!syncScroll || view !== 'split') return
                revealEditorLine(line)
              }}
              scrollPercentage={syncScroll && view === 'split' ? previewScrollPct : undefined}
              scrollToLine={syncScroll && view === 'split' ? previewAnchorLine : undefined}
              stickToBottom={syncScroll ? lockActive : false}
              documentIdOverride={documentId}
              onToggleTask={readOnly ? undefined : onToggleTask}
              taskToggleDisabled={readOnly}
            />
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
