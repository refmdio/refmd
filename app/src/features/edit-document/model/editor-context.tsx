import type * as monaco from 'monaco-editor'
import React, { createContext, useContext, useMemo, useState } from 'react'

type Ctx = {
  editor: monaco.editor.IStandaloneCodeEditor | null
  setEditor: (ed: monaco.editor.IStandaloneCodeEditor | null) => void
}

const EditorCtx = createContext<Ctx | null>(null)

export function EditorProvider({ children }: { children: React.ReactNode }) {
  const [editor, setEditor] = useState<monaco.editor.IStandaloneCodeEditor | null>(null)
  const value = useMemo(() => ({ editor, setEditor }), [editor])
  return <EditorCtx.Provider value={value}>{children}</EditorCtx.Provider>
}

export function useEditorContext() {
  const v = useContext(EditorCtx)
  if (!v) throw new Error('useEditorContext must be used within EditorProvider')
  return v
}

