import type * as monacoNs from 'monaco-editor'
import { useCallback } from 'react'
import { toast } from 'sonner'

import { useEditorContext } from '@/features/edit-document/model/editor-context'

export function useEditorUploads(documentId: string, readOnly?: boolean) {
  const { editor } = useEditorContext()
  const uploadFiles = useCallback(async (files: File[]) => {
    if (readOnly) return
    if (!files?.length) return
    const { uploadAttachment } = await import('@/entities/file')
    for (const f of files) {
      try {
        const resp = await uploadAttachment(documentId, f)
        const name: string = (resp as any).filename || f.name
        const ed = editor
        if (ed) {
          const selection = ed.getSelection() as monacoNs.Selection | null
          let targetRange: monacoNs.IRange | null = selection || null
          if (!targetRange) {
            try {
              const model = ed.getModel()
              if (model) {
                const lastLine = model.getLineCount()
                const lastCol = model.getLineMaxColumn(lastLine)
                targetRange = {
                  startLineNumber: lastLine,
                  startColumn: lastCol,
                  endLineNumber: lastLine,
                  endColumn: lastCol,
                }
              }
            } catch {}
          }
          if (!targetRange) continue
          const rel = `./attachments/${(resp as any).filename || f.name}`
          const text = f.type.startsWith('image/') ? `![${name}](${rel})` : `[${name}](${rel})`
          ed.executeEdits('insertUpload', [{ range: targetRange, text, forceMoveMarkers: true }])
          ed.focus()
        }
      } catch {
        try { toast.error(`Failed to upload: ${f.name}`) } catch {}
      }
    }
  }, [documentId, editor, readOnly])

  return { uploadFiles }
}
