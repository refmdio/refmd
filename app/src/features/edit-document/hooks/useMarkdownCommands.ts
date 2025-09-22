import type * as monacoNs from 'monaco-editor'
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
  editorRef: React.MutableRefObject<monacoNs.editor.IStandaloneCodeEditor | null>,
) {
  const applyEdit = useCallback(
    (fn: (editor: monacoNs.editor.IStandaloneCodeEditor) => void) => {
      const editor = editorRef.current
      if (!editor) return
      fn(editor)
    },
    [editorRef],
  )

  const insertAround = useCallback(
    (start: string, end: string = start) =>
      applyEdit((editor) => {
        const selection = editor.getSelection()
        if (!selection) return
        const model = editor.getModel()
        if (!model) return
        const selected = model.getValueInRange(selection)
        editor.executeEdits('insertAround', [
          { range: selection, text: `${start}${selected}${end}`, forceMoveMarkers: true },
        ])
        editor.focus()
      }),
    [applyEdit],
  )

  const prefixLines = useCallback(
    (prefix: string) =>
      applyEdit((editor) => {
        const selection = editor.getSelection()
        if (!selection) return
        const model = editor.getModel()
        if (!model) return
        const startLine = selection.startLineNumber
        const endLine = selection.endLineNumber
        const edits: monacoNs.editor.IIdentifiedSingleEditOperation[] = []
        for (let line = startLine; line <= endLine; line += 1) {
          const range = new (window as any).monaco.Range(line, 1, line, 1)
          edits.push({ range, text: prefix })
        }
        editor.executeEdits('prefixLines', edits)
        editor.focus()
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
          return applyEdit((editor) => {
            const selection = editor.getSelection()
            if (!selection) return
            const model = editor.getModel()
            if (!model) return
            const text = model.getValueInRange(selection)
            if (!text.includes('\n')) {
              editor.executeEdits('codeInline', [
                { range: selection, text: `\`${text}\``, forceMoveMarkers: true },
              ])
            } else {
              editor.executeEdits('codeBlock', [
                {
                  range: selection,
                  text: `\n\n\`\`\`\n${text}\n\`\`\`\n\n`,
                  forceMoveMarkers: true,
                },
              ])
            }
          })
        case 'table':
          return applyEdit((editor) => {
            const selection = editor.getSelection()
            if (!selection) return
            const snippet = '\n\n| Header 1 | Header 2 |\n| --- | --- |\n| Cell 1 | Cell 2 |\n\n'
            editor.executeEdits('table', [
              { range: selection, text: snippet, forceMoveMarkers: true },
            ])
          })
        case 'horizontal-rule':
          return applyEdit((editor) => {
            const selection = editor.getSelection()
            if (!selection) return
            editor.executeEdits('hr', [
              { range: selection, text: '\n\n---\n\n', forceMoveMarkers: true },
            ])
          })
        case 'link':
          return applyEdit((editor) => {
            const selection = editor.getSelection()
            if (!selection) return
            const model = editor.getModel()
            if (!model) return
            const text = model.getValueInRange(selection) || 'text'
            const url = prompt('URL?') || 'https://'
            editor.executeEdits('link', [
              { range: selection, text: `[${text}](${url})`, forceMoveMarkers: true },
            ])
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
