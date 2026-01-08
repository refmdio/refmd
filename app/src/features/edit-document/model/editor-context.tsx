import { EditorView } from '@codemirror/view'
import React, { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'

type Ctx = {
  editor: EditorView | null
  setEditor: (ed: EditorView | null) => void
  registerEditor: (ed: EditorView) => () => void
}

const EditorCtx = createContext<Ctx | null>(null)

export function EditorProvider({ children }: { children: React.ReactNode }) {
  const [editor, setEditor] = useState<EditorView | null>(null)
  const editorsRef = useRef<Set<EditorView>>(new Set())

  const registerEditor = useCallback((ed: EditorView) => {
    editorsRef.current.add(ed)
    setEditor((current) => current ?? ed)
    let released = false
    return () => {
      if (released) return
      released = true
      editorsRef.current.delete(ed)
      setEditor((current) => {
        if (current !== ed) return current
        const next = editorsRef.current.values().next().value ?? null
        return next
      })
    }
  }, [])

  const value = useMemo(() => ({ editor, setEditor, registerEditor }), [editor, registerEditor])
  return <EditorCtx.Provider value={value}>{children}</EditorCtx.Provider>
}

export function useEditorContext() {
  const v = useContext(EditorCtx)
  if (!v) throw new Error('useEditorContext must be used within EditorProvider')
  return v
}
