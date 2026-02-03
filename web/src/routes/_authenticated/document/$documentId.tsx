import { createFileRoute } from '@tanstack/react-router'
import { Loader2, AlertCircle, FileX } from 'lucide-react'
import { useDocumentEdit } from '@/features/document-edit'
import { DocumentEditor } from '@/widgets/document-editor'

export const Route = createFileRoute('/_authenticated/document/$documentId')({
  component: DocumentEditorPage,
})

function DocumentEditorPage() {
  const { documentId } = Route.useParams()
  const { document, yDoc, isLoading, error, save } = useDocumentEdit(documentId)

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
        <p className="mt-4 text-muted-foreground">Loading document...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <AlertCircle className="w-8 h-8 text-destructive" />
        <p className="mt-4 text-destructive font-medium">Failed to load document</p>
        <p className="text-sm text-muted-foreground">{error.message}</p>
      </div>
    )
  }

  if (!document || !yDoc) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <FileX className="w-8 h-8 text-muted-foreground" />
        <p className="mt-4 text-muted-foreground">Document not found</p>
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
