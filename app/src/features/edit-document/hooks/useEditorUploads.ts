import type * as monacoNs from 'monaco-editor'
import { useCallback, useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'

import { useEditorContext } from '@/features/edit-document/model/editor-context'

export type UploadStatus =
  | { state: 'idle'; total: 0; completed: 0 }
  | { state: 'uploading'; total: number; completed: number; currentFile?: string }
  | { state: 'success'; total: number; completed: number }
  | { state: 'error'; total: number; completed: number; failed: number }

export function useEditorUploads(documentId: string, readOnly?: boolean, onReadOnlyAttempt?: () => void) {
  const { editor } = useEditorContext()
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>({ state: 'idle', total: 0, completed: 0 })
  const resetTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const scheduleReset = useCallback((delay = 2500) => {
    if (resetTimeoutRef.current != null) {
      clearTimeout(resetTimeoutRef.current)
    }
    resetTimeoutRef.current = setTimeout(() => {
      setUploadStatus({ state: 'idle', total: 0, completed: 0 })
      resetTimeoutRef.current = null
    }, delay)
  }, [])

  useEffect(() => () => {
    if (resetTimeoutRef.current != null) {
      clearTimeout(resetTimeoutRef.current)
      resetTimeoutRef.current = null
    }
  }, [])

  const uploadFiles = useCallback(async (files: File[]) => {
    if (readOnly) {
      try { onReadOnlyAttempt?.() } catch {}
      return
    }
    if (!files?.length) return
    const { uploadAttachment } = await import('@/entities/file')
    let completed = 0
    let failed = 0
    setUploadStatus({ state: 'uploading', total: files.length, completed: 0, currentFile: files[0]?.name })
    for (const f of files) {
      setUploadStatus({
        state: 'uploading',
        total: files.length,
        completed,
        currentFile: f.name,
      })
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
        completed += 1
      } catch {
        try { toast.error(`Failed to upload: ${f.name}`) } catch {}
        failed += 1
      }
    }
    if (files.length > 0) {
      if (failed > 0) {
        setUploadStatus({ state: 'error', total: files.length, completed, failed })
      } else {
        setUploadStatus({ state: 'success', total: files.length, completed })
      }
      scheduleReset(failed > 0 ? 4000 : 2500)
    } else {
      setUploadStatus({ state: 'idle', total: 0, completed: 0 })
    }
  }, [documentId, editor, onReadOnlyAttempt, readOnly, scheduleReset])

  return { uploadFiles, uploadStatus }
}
