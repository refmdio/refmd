import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useRef } from 'react'
import { MosaicDocumentWorkspace, useDocumentWorkspace } from '@/widgets/document-workspace'

export const Route = createFileRoute('/_authenticated/document/$documentId')({
  component: DocumentWorkspacePage,
})

function DocumentWorkspacePage() {
  const { documentId } = Route.useParams()
  const { openDocuments, openDocument, setFocusedDocumentId } = useDocumentWorkspace()
  const openedFromRouteRef = useRef<string | null>(null)

  useEffect(() => {
    if (openedFromRouteRef.current === documentId) return
    openedFromRouteRef.current = documentId

    if (openDocuments.has(documentId)) {
      setFocusedDocumentId(documentId)
      return
    }

    openDocument({ id: documentId })
  }, [documentId, openDocument, openDocuments, setFocusedDocumentId])

  return (
    <div className="h-full">
      <MosaicDocumentWorkspace />
    </div>
  )
}
