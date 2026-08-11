import Editor from '@monaco-editor/react'
import type { OnMount } from '@monaco-editor/react'
import { Image as ImageIcon } from 'lucide-react'
import type * as monacoNs from 'monaco-editor'
import { useCallback, useEffect, useRef, useState, type MutableRefObject } from 'react'

type Props = {
  theme: string
  onBeforeMount?: (monaco: typeof import('monaco-editor')) => void
  readOnly?: boolean
  onMount: OnMount
  onUnmount?: (editor: monacoNs.editor.IStandaloneCodeEditor | null) => void
  onDropFiles?: (files: File[]) => Promise<void> | void
  isMobile?: boolean
  vimStatusBarRef: MutableRefObject<HTMLDivElement | null>
  showVimStatusBar?: boolean
}

export default function EditorPane({ theme, onBeforeMount, readOnly, onMount, onUnmount, onDropFiles, isMobile = false, vimStatusBarRef, showVimStatusBar = false }: Props) {
  const [isDragging, setIsDragging] = useState(false)
  const dragCounterRef = useRef(0)
  const editorRef = useRef<monacoNs.editor.IStandaloneCodeEditor | null>(null)
  const onUnmountRef = useRef<typeof onUnmount>(onUnmount)

  useEffect(() => {
    onUnmountRef.current = onUnmount
  }, [onUnmount])

  const handleMount: OnMount = useCallback((editor, monaco) => {
    editorRef.current = editor
    onMount(editor, monaco)
  }, [onMount])

  useEffect(() => {
    return () => {
      const editor = editorRef.current
      editorRef.current = null
      onUnmountRef.current?.(editor)
    }
  }, [])

  return (
    <div
      className="relative flex-1 min-h-0 min-w-0 h-full w-full"
      onDragEnter={(e) => { if (e.dataTransfer?.types?.includes('Files')) { dragCounterRef.current++; setIsDragging(true) } }}
      onDragLeave={() => { dragCounterRef.current = Math.max(0, dragCounterRef.current - 1); if (dragCounterRef.current === 0) setIsDragging(false) }}
      onDragOver={(e) => { if (e.dataTransfer?.types?.includes('Files')) { e.preventDefault(); setIsDragging(true) } }}
      onDrop={async (e) => {
        e.preventDefault()
        const files = Array.from(e.dataTransfer?.files || [])
        setIsDragging(false)
        dragCounterRef.current = 0
        if (files.length > 0) { try { await onDropFiles?.(files as File[]) } catch {} }
      }}
    >
      <Editor
        theme={theme as any}
        height="100%"
        defaultLanguage="markdown"
        beforeMount={onBeforeMount as any}
        options={{
          // Disable bracket pair colorization; semantic highlighting option is not available in this Monaco version
          bracketPairColorization: { enabled: false },
          automaticLayout: true,
          minimap: { enabled: false },
          glyphMargin: true,
          wordWrap: 'on',
          // Needed so zero-width comment-marker decorations affect wrap width.
          // Without this, `word<!--comment:…-->` wraps as one token and the
          // commented word sits alone on a soft-wrapped line.
          wrappingStrategy: 'advanced',
          disableMonospaceOptimizations: true,
          // Comment anchors insert U+200B so wrap can break after the quote.
          // Without this, Monaco draws an orange unicode-highlight box there.
          unicodeHighlight: {
            allowedCharacters: { '\u200B': true },
          },
          scrollBeyondLastLine: true,
          readOnly,
          domReadOnly: readOnly,
          suggestOnTriggerCharacters: true,
          quickSuggestions: { other: true, comments: true, strings: true },
          quickSuggestionsDelay: 0,
          detectIndentation: false,
          tabSize: 4,
          insertSpaces: true,
          fontSize: isMobile ? 17 : 14,
          lineHeight: isMobile ? 26 : 22,
        }}
        onMount={handleMount}
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
