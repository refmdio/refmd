import type { OnMount } from '@monaco-editor/react'
import type * as monacoNs from 'monaco-editor'
import { useCallback, useEffect, useRef, useState } from 'react'
import { MonacoBinding } from 'y-monaco'
import type { Awareness } from 'y-protocols/awareness'
import type * as Y from 'yjs'

export type UseMonacoBindingParams = {
  doc: Y.Doc
  awareness: Awareness
  language?: string
  onTextChange?: (text: string) => void
}

export function useMonacoBinding(params: UseMonacoBindingParams) {
  const { doc, awareness, language = 'markdown', onTextChange } = params

  const editorRef = useRef<monacoNs.editor.IStandaloneCodeEditor | null>(null)
  const modelRef = useRef<monacoNs.editor.ITextModel | null>(null)
  const bindingRef = useRef<MonacoBinding | null>(null)
  const [text, setText] = useState('')

  const onMount: OnMount = useCallback((editor, monaco) => {
    editorRef.current = editor
    const model = monaco.editor.createModel('', language)
    editor.setModel(model)
    modelRef.current = model

    const ytext = doc.getText('content')
    const editors = new Set([editor])
    bindingRef.current = new MonacoBinding(ytext, model, editors, awareness)

    const sub = model.onDidChangeContent(() => {
      const v = model.getValue()
      setText(v)
      try {
        if (typeof onTextChange === 'function') onTextChange(v)
        // Support wiring after hook init (Editor side)
        const anyMount = onMount as any
        if (typeof anyMount._onTextChange === 'function') anyMount._onTextChange(v)
        // Notify caret-at-end status for scroll lock logic
        try {
          const ed = editorRef.current
          const pos = ed?.getPosition?.()
          const lineCount = model.getLineCount()
          const isAtEnd = !!pos && pos.lineNumber >= lineCount
          if (typeof anyMount._onCaretAtEnd === 'function') anyMount._onCaretAtEnd(isAtEnd)
        } catch {}
      } catch {}
    })
    setText(model.getValue())

    ;(editor as any).__disposeChange = () => {
      try { sub.dispose() } catch {}
    }
  }, [doc, awareness, language, onTextChange])

  useEffect(() => {
    const ytext = doc.getText('content')
    const update = () => {
      const value = ytext.toString()
      setText(value)
      try { onTextChange?.(value) } catch {}
    }
    update()
    const observer = () => update()
    ytext.observe(observer)
    return () => { try { ytext.unobserve(observer) } catch {} }
  }, [doc, onTextChange])

  useEffect(() => {
    return () => {
      try { bindingRef.current?.destroy?.() } catch {}
      try { modelRef.current?.dispose?.() } catch {}
      bindingRef.current = null
      modelRef.current = null
      editorRef.current = null
    }
  }, [])

  return {
    onMount,
    text,
    editorRef,
    modelRef,
    bindingRef,
  }
}

export type UseMonacoBindingReturn = ReturnType<typeof useMonacoBinding>
