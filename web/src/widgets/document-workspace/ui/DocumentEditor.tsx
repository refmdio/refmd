/**
 * Document Editor Component
 *
 * CodeMirror 6 editor integrated with Yjs for CRDT state management.
 */

import { useEffect, useRef } from 'react'
import { EditorState, Compartment } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import { markdown } from '@codemirror/lang-markdown'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'
import { basicSetup } from 'codemirror'
import { yCollab } from 'y-codemirror.next'
import * as Y from 'yjs'
import { useTheme } from '@/shared/context'

// Compartments for dynamic reconfiguration without editor recreation
const themeCompartment = new Compartment()
const editableCompartment = new Compartment()
const keymapCompartment = new Compartment()

interface ThemeColors {
  linkColor: string
  monospaceBg: string
  quoteColor: string
  selectionOpacity: string
}

const LIGHT_COLORS: ThemeColors = {
  linkColor: '#6e63d6',
  monospaceBg: 'rgba(0,0,0,0.05)',
  quoteColor: '#596272',
  selectionOpacity: '0.2',
}

const DARK_COLORS: ThemeColors = {
  linkColor: '#8f86e8',
  monospaceBg: 'rgba(255,255,255,0.05)',
  quoteColor: '#9aa1b0',
  selectionOpacity: '0.3',
}

function createEditorTheme(dark: boolean) {
  const colors = dark ? DARK_COLORS : LIGHT_COLORS
  return EditorView.theme(
    {
      '&': {
        height: '100%',
        fontSize: '14px',
        backgroundColor: 'var(--background)',
        color: 'var(--foreground)',
      },
      '.cm-scroller': {
        overflow: 'auto',
        fontFamily: 'var(--font-mono)',
      },
      '.cm-content': {
        padding: '1rem',
        caretColor: 'var(--foreground)',
      },
      '.cm-cursor': {
        borderLeftColor: 'var(--foreground)',
      },
      '.cm-activeLine': {
        backgroundColor: 'var(--muted)',
      },
      '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
        backgroundColor: 'var(--accent)',
        opacity: colors.selectionOpacity,
      },
      '.cm-gutters': {
        backgroundColor: 'var(--background)',
        color: 'var(--muted-foreground)',
        border: 'none',
      },
      '.cm-activeLineGutter': {
        backgroundColor: 'var(--muted)',
      },
      '.cm-lineNumbers .cm-gutterElement': {
        color: 'var(--muted-foreground)',
      },
    },
    { dark }
  )
}

function createHighlighting(dark: boolean) {
  const colors = dark ? DARK_COLORS : LIGHT_COLORS
  return HighlightStyle.define([
    { tag: tags.heading1, fontWeight: 'bold', fontSize: '1.5em' },
    { tag: tags.heading2, fontWeight: 'bold', fontSize: '1.3em' },
    { tag: tags.heading3, fontWeight: 'bold', fontSize: '1.1em' },
    { tag: tags.heading, fontWeight: 'bold' },
    { tag: tags.emphasis, fontStyle: 'italic' },
    { tag: tags.strong, fontWeight: 'bold' },
    { tag: tags.link, color: colors.linkColor, textDecoration: 'underline' },
    { tag: tags.url, color: colors.linkColor },
    { tag: tags.monospace, fontFamily: 'var(--font-mono)', backgroundColor: colors.monospaceBg },
    { tag: tags.quote, color: colors.quoteColor, fontStyle: 'italic' },
    { tag: tags.strikethrough, textDecoration: 'line-through' },
    { tag: tags.processingInstruction, color: colors.quoteColor },
  ])
}

const lightTheme = createEditorTheme(false)
const darkTheme = createEditorTheme(true)
const lightHighlighting = createHighlighting(false)
const darkHighlighting = createHighlighting(true)

export interface DocumentEditorProps {
  documentId: string
  yDoc: Y.Doc
  onSave: () => void
  readOnly?: boolean
}

export function DocumentEditor({
  documentId,
  yDoc,
  onSave,
  readOnly = false,
}: DocumentEditorProps) {
  const editorRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)
  const onSaveRef = useRef(onSave)
  onSaveRef.current = onSave
  const readOnlyRef = useRef(readOnly)
  readOnlyRef.current = readOnly
  const { isDarkMode } = useTheme()

  // Update theme when dark mode changes
  useEffect(() => {
    if (viewRef.current) {
      viewRef.current.dispatch({
        effects: themeCompartment.reconfigure([
          isDarkMode ? darkTheme : lightTheme,
          syntaxHighlighting(isDarkMode ? darkHighlighting : lightHighlighting),
        ]),
      })
    }
  }, [isDarkMode])

  // Update editable state without recreating editor
  useEffect(() => {
    if (viewRef.current) {
      viewRef.current.dispatch({
        effects: editableCompartment.reconfigure(EditorView.editable.of(!readOnly)),
      })
    }
  }, [readOnly])

  // Update save keymap without recreating editor
  useEffect(() => {
    if (viewRef.current) {
      viewRef.current.dispatch({
        effects: keymapCompartment.reconfigure(
          keymap.of([{
            key: 'Mod-s',
            run: () => {
              if (!readOnlyRef.current) onSaveRef.current()
              return true
            },
          }])
        ),
      })
    }
  }, [onSave, readOnly])

  // Create editor once per yDoc/documentId
  useEffect(() => {
    if (!editorRef.current || viewRef.current) {
      return
    }

    // Get Y.Text from Y.Doc (create if not exists)
    const yText = yDoc.getText('content')

    // Create editor state with extensions
    const startState = EditorState.create({
      doc: yText.toString(),
      extensions: [
        basicSetup,
        markdown(),
        themeCompartment.of([
          isDarkMode ? darkTheme : lightTheme,
          syntaxHighlighting(isDarkMode ? darkHighlighting : lightHighlighting),
        ]),
        editableCompartment.of(EditorView.editable.of(!readOnly)),
        // Yjs collaboration extension
        yCollab(yText, null, { undoManager: new Y.UndoManager(yText) }),
        // Keyboard shortcuts
        keymapCompartment.of(
          keymap.of([{
            key: 'Mod-s',
            run: () => {
              if (!readOnlyRef.current) onSaveRef.current()
              return true
            },
          }])
        ),
      ],
    })

    // Create editor view
    const view = new EditorView({
      state: startState,
      parent: editorRef.current,
    })

    viewRef.current = view

    // Cleanup on unmount
    return () => {
      view.destroy()
      viewRef.current = null
    }
  }, [yDoc, documentId])

  return (
    <div ref={editorRef} className="h-full overflow-hidden" data-testid="document-editor" />
  )
}
