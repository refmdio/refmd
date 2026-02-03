/**
 * Preview Panel
 *
 * Markdown preview panel for use within mosaic workspace.
 */

import { useEffect } from 'react'
import { Loader2, AlertCircle } from 'lucide-react'
import { useDocumentEdit } from '@/features/document-edit'
import { MarkdownPreview } from '@/widgets/document-editor'
import { useDocumentWorkspace } from '../model/DocumentWorkspaceContext'

interface PreviewPanelProps {
  documentId: string
}

export function PreviewPanel({ documentId }: PreviewPanelProps) {
  const { document, content, isLoading, error } = useDocumentEdit(documentId)
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

  if (!document) {
    return (
      <div className="flex items-center justify-center h-full bg-background text-muted-foreground">
        Document not found
      </div>
    )
  }

  return <MarkdownPreview content={content} className="h-full" />
}
