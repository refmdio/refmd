/**
 * CodeMirror Editor Component
 *
 * CodeMirror 6 editor integrated with Yjs for CRDT state management.
 */

import { useEffect, useRef } from 'react'
import { EditorState, Compartment, Transaction } from '@codemirror/state'
import { EditorView, ViewPlugin, keymap } from '@codemirror/view'
import type { ViewUpdate } from '@codemirror/view'
import { markdown } from '@codemirror/lang-markdown'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'
import { basicSetup } from 'codemirror'
import { yCollab, ySyncFacet } from 'y-codemirror.next'
import * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import { useTheme } from '@/shared/context'
import './codemirror-cursors.css'

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

/**
 * CM ViewPlugin that detects genuine local user edits and notifies auto-sync.
 *
 * We only notify for doc-changing transactions that carry a user-event
 * annotation. This avoids false positives from remote sync reconciliation and
 * extension normalization passes that are not direct user interaction.
 */
function localEditNotifier(onLocalEdit: () => void) {
  const isLocalUserEdit = (tr: Transaction): boolean => {
    if (!tr.docChanged) return false
    return (
      tr.isUserEvent('input') ||
      tr.isUserEvent('delete') ||
      tr.isUserEvent('move') ||
      tr.isUserEvent('undo') ||
      tr.isUserEvent('redo')
    )
  }

  return ViewPlugin.fromClass(
    class {
      update(update: ViewUpdate) {
        if (!update.docChanged) return
        if (update.transactions.some(isLocalUserEdit)) {
          onLocalEdit()
        }
      }
    },
  )
}

export interface CodeMirrorEditorProps {
  documentId: string
  yDoc: Y.Doc
  awareness: Awareness | null
  onLocalEdit?: () => void
  readOnly?: boolean
}

export function CodeMirrorEditor({
  documentId,
  yDoc,
  awareness,
  onLocalEdit,
  readOnly = false,
}: CodeMirrorEditorProps) {
  const editorRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)
  const onLocalEditRef = useRef(onLocalEdit)
  onLocalEditRef.current = onLocalEdit
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

  // Suppress browser "Save As" dialog on Mod-s
  useEffect(() => {
    if (viewRef.current) {
      viewRef.current.dispatch({
        effects: keymapCompartment.reconfigure(
          keymap.of([{
            key: 'Mod-s',
            run: () => true,
          }])
        ),
      })
    }
  }, [])

  // Create editor once per yDoc/documentId
  useEffect(() => {
    if (!editorRef.current || viewRef.current) {
      return
    }

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
        // Yjs collaboration extension (must be before localEditNotifier so
        // yCollab syncs CM → Y.Text before auto-sync computes the diff)
        yCollab(yText, awareness, { undoManager: new Y.UndoManager(yText) }),
        // Detect user-originated CM edits and notify auto-sync via callback prop
        localEditNotifier(() => onLocalEditRef.current?.()),
        // Suppress browser "Save As" dialog
        keymapCompartment.of(
          keymap.of([{
            key: 'Mod-s',
            run: () => true,
          }])
        ),
      ],
    })

    // Wrap CM updates in a Y.js transaction to defer Y.Text observer
    // firing until after the CM update completes. Without this, the
    // bridge's textObserver runs syncTextToProsemirror during the CM
    // update, and if a canonical write-back occurs, yCollab's observer
    // dispatches to CM — causing a reentrant "Calls to EditorView.update
    // are not allowed" crash.
    //
    // The origin MUST be the YSyncConfig from ySyncFacet (the same object
    // yCollab uses internally). Nested Y.js transact merges into the
    // outer transaction, so the outer origin wins. If we used a different
    // origin (e.g. a string), yCollab's observer would not recognise its
    // own Y.Text writes and would re-apply them to CM, corrupting content.
    const view = new EditorView({
      state: startState,
      parent: editorRef.current,
      dispatchTransactions(trs) {
        const origin = view.state.facet(ySyncFacet)
        yDoc.transact(() => {
          view.update(trs)
        }, origin)
      },
    })

    viewRef.current = view

    return () => {
      view.destroy()
      viewRef.current = null
    }
  }, [yDoc, documentId, awareness])

  return (
    <div ref={editorRef} className="h-full overflow-hidden" data-testid="document-editor" />
  )
}
