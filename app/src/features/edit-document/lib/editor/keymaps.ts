import { keymap, KeyBinding } from '@codemirror/view'
import { Extension } from '@codemirror/state'
import { EditorView } from '@codemirror/view'

export type MarkdownAction =
  | 'bold'
  | 'italic'
  | 'strikethrough'
  | 'code'
  | 'link'
  | 'heading1'
  | 'heading2'
  | 'heading3'
  | 'bulletList'
  | 'numberedList'
  | 'taskList'
  | 'blockquote'
  | 'codeBlock'
  | 'horizontalRule'

export interface MarkdownKeymapConfig {
  onAction?: (action: MarkdownAction) => void
}

function wrapSelection(view: EditorView, before: string, after: string): boolean {
  const { from, to } = view.state.selection.main
  const selectedText = view.state.sliceDoc(from, to)

  view.dispatch({
    changes: {
      from,
      to,
      insert: `${before}${selectedText}${after}`,
    },
    selection: {
      anchor: from + before.length,
      head: to + before.length,
    },
  })
  view.focus()
  return true
}

function insertAtLineStart(view: EditorView, prefix: string): boolean {
  const line = view.state.doc.lineAt(view.state.selection.main.head)
  const content = view.state.sliceDoc(line.from, line.to)

  view.dispatch({
    changes: {
      from: line.from,
      to: line.to,
      insert: `${prefix}${content}`,
    },
    selection: { anchor: line.from + prefix.length + content.length },
  })
  view.focus()
  return true
}

export function createMarkdownKeymap(config?: MarkdownKeymapConfig): Extension {
  const bindings: KeyBinding[] = [
    {
      key: 'Mod-b',
      run: (view) => {
        config?.onAction?.('bold')
        return wrapSelection(view, '**', '**')
      },
    },
    {
      key: 'Mod-i',
      run: (view) => {
        config?.onAction?.('italic')
        return wrapSelection(view, '_', '_')
      },
    },
    {
      key: 'Mod-Shift-s',
      run: (view) => {
        config?.onAction?.('strikethrough')
        return wrapSelection(view, '~~', '~~')
      },
    },
    {
      key: 'Mod-e',
      run: (view) => {
        config?.onAction?.('code')
        return wrapSelection(view, '`', '`')
      },
    },
    {
      key: 'Mod-k',
      run: (view) => {
        config?.onAction?.('link')
        const { from, to } = view.state.selection.main
        const selectedText = view.state.sliceDoc(from, to)

        if (selectedText) {
          view.dispatch({
            changes: {
              from,
              to,
              insert: `[${selectedText}](url)`,
            },
            selection: { anchor: from + selectedText.length + 3, head: from + selectedText.length + 6 },
          })
        } else {
          view.dispatch({
            changes: {
              from,
              insert: '[](url)',
            },
            selection: { anchor: from + 1 },
          })
        }
        view.focus()
        return true
      },
    },
    {
      key: 'Mod-1',
      run: (view) => {
        config?.onAction?.('heading1')
        return insertAtLineStart(view, '# ')
      },
    },
    {
      key: 'Mod-2',
      run: (view) => {
        config?.onAction?.('heading2')
        return insertAtLineStart(view, '## ')
      },
    },
    {
      key: 'Mod-3',
      run: (view) => {
        config?.onAction?.('heading3')
        return insertAtLineStart(view, '### ')
      },
    },
    {
      key: 'Mod-Shift-8',
      run: (view) => {
        config?.onAction?.('bulletList')
        return insertAtLineStart(view, '- ')
      },
    },
    {
      key: 'Mod-Shift-7',
      run: (view) => {
        config?.onAction?.('numberedList')
        return insertAtLineStart(view, '1. ')
      },
    },
    {
      key: 'Mod-Shift-9',
      run: (view) => {
        config?.onAction?.('taskList')
        return insertAtLineStart(view, '- [ ] ')
      },
    },
    {
      key: 'Mod-Shift-.',
      run: (view) => {
        config?.onAction?.('blockquote')
        return insertAtLineStart(view, '> ')
      },
    },
  ]

  return keymap.of(bindings)
}

export function createCustomKeymap(bindings: KeyBinding[]): Extension {
  return keymap.of(bindings)
}
