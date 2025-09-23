import Editor from '@monaco-editor/react'
import type { OnMount } from '@monaco-editor/react'
import { Image as ImageIcon } from 'lucide-react'
import { useRef, useState } from 'react'

type Props = {
  theme: string
  readOnly?: boolean
  onMount: OnMount
  onDropFiles?: (files: File[]) => Promise<void> | void
  isMobile?: boolean
}

export default function EditorPane({ theme, readOnly, onMount, onDropFiles, isMobile = false }: Props) {
  const [isDragging, setIsDragging] = useState(false)
  const dragCounterRef = useRef(0)

  return (
    <div
      className="relative flex-1 min-h-0 h-full"
      onDragEnter={(e) => { if (e.dataTransfer?.types?.includes('Files')) { dragCounterRef.current++; setIsDragging(true) } }}
      onDragLeave={() => { dragCounterRef.current = Math.max(0, dragCounterRef.current - 1); if (dragCounterRef.current === 0) setIsDragging(false) }}
      onDragOver={(e) => { if (e.dataTransfer?.types?.includes('Files')) { e.preventDefault(); setIsDragging(true) } }}
      onDrop={async (e) => {
        e.preventDefault()
        const files = Array.from(e.dataTransfer?.files || [])
        setIsDragging(false)
        dragCounterRef.current = 0
        if (!readOnly && files.length > 0) { try { await onDropFiles?.(files as File[]) } catch {} }
      }}
    >
      <Editor
        theme={theme as any}
        height="100%"
        defaultLanguage="markdown"
        options={{
          automaticLayout: true,
          minimap: { enabled: false },
          wordWrap: 'on',
          scrollBeyondLastLine: true,
          readOnly,
          suggestOnTriggerCharacters: true,
          quickSuggestions: { other: true, comments: true, strings: true },
          quickSuggestionsDelay: 0,
          detectIndentation: false,
          tabSize: 2,
          insertSpaces: true,
          fontSize: isMobile ? 17 : 14,
          lineHeight: isMobile ? 26 : 22,
        }}
        onMount={onMount}
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
