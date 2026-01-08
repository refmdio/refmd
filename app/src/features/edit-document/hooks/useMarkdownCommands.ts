import { EditorView } from '@codemirror/view'
import { useCallback } from 'react'

export type MarkdownCommand =
  | 'bold'
  | 'italic'
  | 'strikethrough'
  | 'heading'
  | 'unordered-list'
  | 'ordered-list'
  | 'task-list'
  | 'quote'
  | 'code'
  | 'table'
  | 'horizontal-rule'
  | 'link'

export function useMarkdownCommands(
  editorRef: React.MutableRefObject<EditorView | null>,
) {
  const applyEdit = useCallback(
    (fn: (view: EditorView) => void) => {
      const view = editorRef.current
      if (!view) return
      fn(view)
    },
    [editorRef],
  )

  const insertAround = useCallback(
    (start: string, end: string = start) =>
      applyEdit((view) => {
        const { from, to } = view.state.selection.main
        const selected = view.state.sliceDoc(from, to)
        view.dispatch({
          changes: { from, to, insert: `${start}${selected}${end}` },
          selection: { anchor: from + start.length, head: to + start.length },
        })
        view.focus()
      }),
    [applyEdit],
  )

  const prefixLines = useCallback(
    (prefix: string) =>
      applyEdit((view) => {
        const { from, to } = view.state.selection.main
        const startLine = view.state.doc.lineAt(from)
        const endLine = view.state.doc.lineAt(to)
        const changes: { from: number; insert: string }[] = []

        for (let lineNum = startLine.number; lineNum <= endLine.number; lineNum++) {
          const line = view.state.doc.line(lineNum)
          changes.push({ from: line.from, insert: prefix })
        }

        view.dispatch({ changes })
        view.focus()
      }),
    [applyEdit],
  )

  const runCommand = useCallback(
    (command: MarkdownCommand, value?: number) => {
      switch (command) {
        case 'bold':
          return insertAround('**')
        case 'italic':
          return insertAround('*')
        case 'strikethrough':
          return insertAround('~~')
        case 'heading':
          return prefixLines('# '.repeat(value || 1))
        case 'unordered-list':
          return prefixLines('- ')
        case 'ordered-list':
          return prefixLines('1. ')
        case 'task-list':
          return prefixLines('- [ ] ')
        case 'quote':
          return prefixLines('> ')
        case 'code':
          return applyEdit((view) => {
            const { from, to } = view.state.selection.main
            const text = view.state.sliceDoc(from, to)
            if (!text.includes('\n')) {
              view.dispatch({
                changes: { from, to, insert: `\`${text}\`` },
                selection: { anchor: from + 1, head: to + 1 },
              })
            } else {
              view.dispatch({
                changes: { from, to, insert: `\n\n\`\`\`\n${text}\n\`\`\`\n\n` },
              })
            }
            view.focus()
          })
        case 'table':
          return applyEdit((view) => {
            const { from, to } = view.state.selection.main
            const snippet = '\n\n| Header 1 | Header 2 |\n| --- | --- |\n| Cell 1 | Cell 2 |\n\n'
            view.dispatch({
              changes: { from, to, insert: snippet },
            })
            view.focus()
          })
        case 'horizontal-rule':
          return applyEdit((view) => {
            const { from, to } = view.state.selection.main
            view.dispatch({
              changes: { from, to, insert: '\n\n---\n\n' },
            })
            view.focus()
          })
        case 'link':
          return applyEdit((view) => {
            const { from, to } = view.state.selection.main
            const text = view.state.sliceDoc(from, to) || 'text'
            const url = prompt('URL?') || 'https://'
            view.dispatch({
              changes: { from, to, insert: `[${text}](${url})` },
            })
            view.focus()
          })
        default:
          return undefined
      }
    },
    [applyEdit, insertAround, prefixLines],
  )

  return {
    runCommand,
    applyEdit,
    insertAround,
    prefixLines,
  }
}

export default useMarkdownCommands
