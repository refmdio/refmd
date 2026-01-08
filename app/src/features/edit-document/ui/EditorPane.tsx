import { EditorState, Extension } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { Image as ImageIcon } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type MutableRefObject } from 'react'

import { createEditorExtensions, themeCompartment, readOnlyCompartment, getThemeExtension } from '@/features/edit-document/lib/editor'

type Props = {
  isDarkMode: boolean
  readOnly?: boolean
  isMobile?: boolean
  extensions?: Extension[]
  onViewCreated?: (view: EditorView) => void
  onDropFiles?: (files: File[]) => Promise<void> | void
  vimStatusBarRef: MutableRefObject<HTMLDivElement | null>
  showVimStatusBar?: boolean
}

export default function EditorPane({
  isDarkMode,
  readOnly = false,
  isMobile = false,
  extensions = [],
  onViewCreated,
  onDropFiles,
  vimStatusBarRef,
  showVimStatusBar = false,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const dragCounterRef = useRef(0)

  // Create and mount the editor
  useEffect(() => {
    if (!containerRef.current) return

    const baseExtensions = createEditorExtensions({
      isDarkMode,
      readOnly,
      vimMode: false,
      isMobile,
      lineWrapping: true,
    })

    const state = EditorState.create({
      doc: '',
      extensions: [...baseExtensions, ...extensions],
    })

    const view = new EditorView({
      state,
      parent: containerRef.current,
    })

    viewRef.current = view
    onViewCreated?.(view)

    return () => {
      view.destroy()
      viewRef.current = null
    }
  }, []) // Only run once on mount

  // Update theme when isDarkMode changes
  useEffect(() => {
    const view = viewRef.current
    if (!view) return

    view.dispatch({
      effects: themeCompartment.reconfigure(getThemeExtension(isDarkMode)),
    })
  }, [isDarkMode])

  // Update readOnly when it changes
  useEffect(() => {
    const view = viewRef.current
    if (!view) return

    view.dispatch({
      effects: readOnlyCompartment.reconfigure(EditorState.readOnly.of(readOnly)),
    })
  }, [readOnly])

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    if (e.dataTransfer?.types?.includes('Files')) {
      dragCounterRef.current++
      setIsDragging(true)
    }
  }, [])

  const handleDragLeave = useCallback(() => {
    dragCounterRef.current = Math.max(0, dragCounterRef.current - 1)
    if (dragCounterRef.current === 0) setIsDragging(false)
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (e.dataTransfer?.types?.includes('Files')) {
      e.preventDefault()
      setIsDragging(true)
    }
  }, [])

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault()
      const files = Array.from(e.dataTransfer?.files || [])
      setIsDragging(false)
      dragCounterRef.current = 0
      if (files.length > 0) {
        try {
          await onDropFiles?.(files)
        } catch {}
      }
    },
    [onDropFiles],
  )

  return (
    <div
      className="relative flex-1 min-h-0 min-w-0 h-full w-full"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <div
        ref={containerRef}
        className="h-full w-full overflow-auto [&_.cm-editor]:h-full [&_.cm-editor]:outline-none [&_.cm-scroller]:overflow-auto"
      />
      <div
        ref={vimStatusBarRef}
        role="status"
        aria-live="polite"
        aria-hidden={!showVimStatusBar}
        className={`pointer-events-none absolute bottom-3 left-3 rounded-md border border-border/40 bg-muted/95 px-3 py-1 text-xs font-mono text-muted-foreground shadow-sm whitespace-pre-wrap ${showVimStatusBar ? '' : 'hidden'}`}
      />
      {isDragging && !readOnly && (
        <div className="absolute inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center">
          <div className="text-center">
            <ImageIcon className="h-10 w-10 mx-auto mb-2 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">Drop to upload files</p>
          </div>
        </div>
      )}
    </div>
  )
}
