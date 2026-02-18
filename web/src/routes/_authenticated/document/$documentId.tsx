import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect, useRef } from 'react'
import { MosaicDocumentWorkspace, useDocumentWorkspace } from '@/widgets/document-workspace'

export const Route = createFileRoute('/_authenticated/document/$documentId')({
  component: DocumentWorkspacePage,
})

function DocumentWorkspacePage() {
  const { documentId } = Route.useParams()
  const navigate = useNavigate()
  const { openDocuments, openDocument, setFocusedDocumentId, focusedDocumentId } = useDocumentWorkspace()
  const openedFromRouteRef = useRef<string | null>(null)

  useEffect(() => {
    // Already open — just focus
    if (openDocuments.has(documentId)) {
      setFocusedDocumentId(documentId)
      return
    }

    // Guard against double-open (React Strict Mode)
    if (openedFromRouteRef.current === documentId) return
    openedFromRouteRef.current = documentId

    openDocument({ id: documentId })
  }, [documentId, openDocument, openDocuments, setFocusedDocumentId])

  // Navigate away when the document tile is closed while this route is active.
  // Without this, the URL remains at /document/$documentId but the tile is gone.
  useEffect(() => {
    if (openedFromRouteRef.current !== documentId) return
    if (openDocuments.has(documentId)) return

    // Tile was closed — sync URL with actual state
    openedFromRouteRef.current = null
    if (focusedDocumentId && focusedDocumentId !== documentId) {
      navigate({ to: '/document/$documentId', params: { documentId: focusedDocumentId } })
    } else {
      navigate({ to: '/dashboard' })
    }
  }, [documentId, openDocuments, focusedDocumentId, navigate])

  return (
    <div className="h-full">
      <MosaicDocumentWorkspace />
    </div>
  )
}
