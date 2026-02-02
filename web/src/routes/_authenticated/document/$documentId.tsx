import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/_authenticated/document/$documentId')({
  component: DocumentEditorPage,
})

function DocumentEditorPage() {
  const { documentId } = Route.useParams()

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-4">Document Editor</h1>
      <p className="text-muted-foreground">Document: {documentId}</p>
      <p className="text-muted-foreground mt-4">
        Editor will be implemented in Phase 1C-5
      </p>
    </div>
  )
}
