import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect, useRef } from 'react'
import { MosaicDocumentWorkspace, useDocumentWorkspace } from '@/widgets/document-workspace'
import { useWorkspaceSelection } from '@/entities/workspace'

export const Route = createFileRoute('/_authenticated/document/$documentId')({
  component: DocumentWorkspacePage,
})

function DocumentWorkspacePage() {
  const { documentId } = Route.useParams()
  const navigate = useNavigate()
  const { currentWorkspaceId } = useWorkspaceSelection()
  const { openDocuments, openDocument, setFocusedDocumentId, focusedDocumentId } = useDocumentWorkspace()

  const wasOpenRef = useRef(false)
  const openedRef = useRef<string | null>(null)
  // Track which workspace this document was opened under
  const workspaceRef = useRef(currentWorkspaceId)

  // Keep latest references to avoid stale closures without triggering re-runs
  const openDocumentRef = useRef(openDocument)
  openDocumentRef.current = openDocument
  const setFocusedRef = useRef(setFocusedDocumentId)
  setFocusedRef.current = setFocusedDocumentId
  const openDocsRef = useRef(openDocuments)
  openDocsRef.current = openDocuments

  // Open the document on mount / documentId change.
  // GUARD: only open if workspace hasn't changed since mount (prevents
  // cross-workspace document leakage during workspace switch).
  useEffect(() => {
    if (openedRef.current === documentId) return
    // If workspace changed since this component mounted, don't open — navigate away
    if (workspaceRef.current !== currentWorkspaceId) return

    openedRef.current = documentId
    wasOpenRef.current = false

    if (!openDocsRef.current.has(documentId)) {
      openDocumentRef.current({ id: documentId })
    } else {
      wasOpenRef.current = true
    }
    setFocusedRef.current(documentId)
  }, [documentId, currentWorkspaceId])

  // If workspace changes while on this document route, navigate to workspace
  useEffect(() => {
    if (currentWorkspaceId && currentWorkspaceId !== workspaceRef.current) {
      navigate({ to: '/workspace/$workspaceId', params: { workspaceId: currentWorkspaceId } })
    }
  }, [currentWorkspaceId, navigate])

  // Track open state and navigate away when tile is closed
  useEffect(() => {
    if (openDocuments.has(documentId)) {
      wasOpenRef.current = true
      return
    }
    if (!wasOpenRef.current) return

    wasOpenRef.current = false
    if (focusedDocumentId && focusedDocumentId !== documentId) {
      navigate({ to: '/document/$documentId', params: { documentId: focusedDocumentId } })
    } else {
      navigate({ to: '/workspace' })
    }
  }, [documentId, openDocuments, focusedDocumentId, navigate])

  return (
    <div className="h-full">
      <MosaicDocumentWorkspace />
    </div>
  )
}
