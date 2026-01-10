import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Extension } from '@codemirror/state'
import { EditorView, ViewUpdate } from '@codemirror/view'
import { yCollab } from 'y-codemirror.next'
import type { Awareness } from 'y-protocols/awareness'
import type * as Y from 'yjs'

export type UseEditorBindingParams = {
  doc: Y.Doc
  awareness: Awareness
  onTextChange?: (text: string) => void
  onCaretAtEnd?: (isAtEnd: boolean) => void
}

export function useEditorBinding(params: UseEditorBindingParams) {
  const { doc, awareness, onTextChange, onCaretAtEnd } = params

  const editorRef = useRef<EditorView | null>(null)
  const [text, setText] = useState('')
  const onTextChangeRef = useRef(onTextChange)
  const onCaretAtEndRef = useRef(onCaretAtEnd)

  // Keep refs up to date
  useEffect(() => {
    onTextChangeRef.current = onTextChange
    onCaretAtEndRef.current = onCaretAtEnd
  }, [onTextChange, onCaretAtEnd])

  // EOL normalization
  useEffect(() => {
    const metaMap = doc.getMap('__refmd_internal')
    if (metaMap.get('eol') === 'lf') return
    const ytext = doc.getText('content')
    const current = ytext.toString()
    const hasCR = current.includes('\r')
    doc.transact(() => {
      if (hasCR) {
        const normalized = current.replace(/\r\n?/g, '\n')
        ytext.delete(0, ytext.length)
        ytext.insert(0, normalized)
      }
      metaMap.set('eol', 'lf')
    })
  }, [doc])

  // Observe Y.Text changes for external updates
  useEffect(() => {
    const ytext = doc.getText('content')
    const update = () => {
      const value = ytext.toString()
      setText(value)
      try {
        onTextChangeRef.current?.(value)
      } catch {}
    }
    update()
    const observer = () => update()
    ytext.observe(observer)
    return () => {
      try {
        ytext.unobserve(observer)
      } catch {}
    }
  }, [doc])

  // Create update listener extension for tracking changes
  const updateListenerExtension = useMemo((): Extension => {
    return EditorView.updateListener.of((update: ViewUpdate) => {
      if (update.docChanged) {
        const value = update.state.doc.toString()
        setText(value)
        try {
          onTextChangeRef.current?.(value)
        } catch {}

        // Check if caret is at end of document
        try {
          const { head } = update.state.selection.main
          const docLength = update.state.doc.length
          const isAtEnd = head >= docLength - 1
          onCaretAtEndRef.current?.(isAtEnd)
        } catch {}
      }
    })
  }, [])

  // Create yCollab extension
  const collabExtension = useMemo((): Extension => {
    const ytext = doc.getText('content')
    return yCollab(ytext, awareness, { undoManager: false })
  }, [doc, awareness])

  // Combined extensions for binding
  const bindingExtensions = useMemo((): Extension[] => {
    return [collabExtension, updateListenerExtension]
  }, [collabExtension, updateListenerExtension])

  // Set editor ref callback
  const setEditorView = useCallback((view: EditorView | null) => {
    editorRef.current = view
    if (view) {
      const value = view.state.doc.toString()
      setText(value)
    }
  }, [])

  // Cleanup
  useEffect(() => {
    return () => {
      editorRef.current = null
    }
  }, [])

  // Get initial Y.Text content for editor initialization
  const getInitialContent = useCallback(() => {
    const ytext = doc.getText('content')
    return ytext.toString()
  }, [doc])

  return {
    text,
    editorRef,
    bindingExtensions,
    setEditorView,
    getInitialContent,
  }
}

export type UseEditorBindingReturn = ReturnType<typeof useEditorBinding>
