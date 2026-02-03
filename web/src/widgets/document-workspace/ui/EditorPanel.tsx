/**
 * Editor Panel
 *
 * CodeMirror editor panel for use within mosaic workspace.
 */

import { useEffect } from 'react'
import { Loader2, AlertCircle } from 'lucide-react'
import { useDocumentEdit } from '@/features/document-edit'
import { DocumentEditor } from '@/widgets/document-editor'
import { useDocumentWorkspace } from '../model/DocumentWorkspaceContext'

interface EditorPanelProps {
  documentId: string
}

export function EditorPanel({ documentId }: EditorPanelProps) {
  const { document, yDoc, isLoading, error, save } = useDocumentEdit(documentId)
  const { upsertDocumentMetadata } = useDocumentWorkspace()

  useEffect(() => {
    if (!document) return
    upsertDocumentMetadata({
      id: document.id,
      title: document.title,
      workspaceId: document.workspace_id,
    })
  }, [document, upsertDocumentMetadata])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full bg-background">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-background">
        <AlertCircle className="w-6 h-6 text-destructive" />
        <p className="mt-2 text-sm text-destructive">{error.message}</p>
      </div>
    )
  }

  if (!document || !yDoc) {
    return (
      <div className="flex items-center justify-center h-full bg-background text-muted-foreground">
        Document not found
      </div>
    )
  }

  return (
    <DocumentEditor
      documentId={documentId}
      yDoc={yDoc}
      onSave={save}
      readOnly={document.is_archived}
    />
  )
}
