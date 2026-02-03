/**
 * Document Editor Component
 *
 * CodeMirror 6 editor integrated with Yjs for CRDT state management.
 */

import { useEffect, useRef, useCallback } from 'react'
import { EditorState, Compartment } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import { markdown } from '@codemirror/lang-markdown'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'
import { basicSetup } from 'codemirror'
import { yCollab } from 'y-codemirror.next'
import * as Y from 'yjs'
import { useTheme } from '@/shared/context/ThemeContext'

// Theme compartment for dynamic theme switching
const themeCompartment = new Compartment()

// Light theme matching project colors
const lightTheme = EditorView.theme(
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
      opacity: '0.2',
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
  { dark: false }
)

// Dark theme matching project colors
const darkTheme = EditorView.theme(
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
      opacity: '0.3',
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
  { dark: true }
)

// Syntax highlighting for light mode
const lightHighlighting = HighlightStyle.define([
  { tag: tags.heading1, fontWeight: 'bold', fontSize: '1.5em' },
  { tag: tags.heading2, fontWeight: 'bold', fontSize: '1.3em' },
  { tag: tags.heading3, fontWeight: 'bold', fontSize: '1.1em' },
  { tag: tags.heading, fontWeight: 'bold' },
  { tag: tags.emphasis, fontStyle: 'italic' },
  { tag: tags.strong, fontWeight: 'bold' },
  { tag: tags.link, color: '#6e63d6', textDecoration: 'underline' },
  { tag: tags.url, color: '#6e63d6' },
  { tag: tags.monospace, fontFamily: 'var(--font-mono)', backgroundColor: 'rgba(0,0,0,0.05)' },
  { tag: tags.quote, color: '#596272', fontStyle: 'italic' },
  { tag: tags.strikethrough, textDecoration: 'line-through' },
  { tag: tags.processingInstruction, color: '#596272' },
])

// Syntax highlighting for dark mode
const darkHighlighting = HighlightStyle.define([
  { tag: tags.heading1, fontWeight: 'bold', fontSize: '1.5em' },
  { tag: tags.heading2, fontWeight: 'bold', fontSize: '1.3em' },
  { tag: tags.heading3, fontWeight: 'bold', fontSize: '1.1em' },
  { tag: tags.heading, fontWeight: 'bold' },
  { tag: tags.emphasis, fontStyle: 'italic' },
  { tag: tags.strong, fontWeight: 'bold' },
  { tag: tags.link, color: '#8f86e8', textDecoration: 'underline' },
  { tag: tags.url, color: '#8f86e8' },
  { tag: tags.monospace, fontFamily: 'var(--font-mono)', backgroundColor: 'rgba(255,255,255,0.05)' },
  { tag: tags.quote, color: '#9aa1b0', fontStyle: 'italic' },
  { tag: tags.strikethrough, textDecoration: 'line-through' },
  { tag: tags.processingInstruction, color: '#9aa1b0' },
])

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
  const { isDarkMode } = useTheme()

  // Ctrl+S / Cmd+S save handler
  const handleSave = useCallback(() => {
    if (!readOnly) {
      onSave()
    }
    return true
  }, [onSave, readOnly])

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
        EditorView.editable.of(!readOnly),
        // Yjs collaboration extension
        yCollab(yText, null, { undoManager: new Y.UndoManager(yText) }),
        // Keyboard shortcuts
        keymap.of([
          {
            key: 'Mod-s',
            run: () => {
              handleSave()
              return true
            },
          },
        ]),
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
  }, [yDoc, handleSave, readOnly, documentId, isDarkMode])

  return (
    <div ref={editorRef} className="h-full overflow-hidden" data-testid="document-editor" />
  )
}
