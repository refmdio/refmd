import { useCallback } from 'react'
import { Outlet, useNavigate, useParams } from '@tanstack/react-router'
import { Sidebar } from '@/widgets/sidebar'
import { CreateDocumentDialog } from '@/features/document-create'
import { useDocumentWorkspace } from '@/widgets/document-workspace'
import type { DocumentResponse } from '@/shared/api'

interface AppShellProps {
  effectiveWorkspaceId: string | null | undefined
  onSelectWorkspace: (workspaceId: string) => void
  createDialogOpen: boolean
  setCreateDialogOpen: (open: boolean) => void
  onDocumentCreated: (doc: DocumentResponse) => void
  notificationSlot?: React.ReactNode
  settingsSlot?: React.ReactNode
  onSettingsClick: () => void
}

export function AppShell({
  effectiveWorkspaceId,
  onSelectWorkspace,
  createDialogOpen,
  setCreateDialogOpen,
  onDocumentCreated,
  notificationSlot,
  settingsSlot,
  onSettingsClick,
}: AppShellProps) {
  const navigate = useNavigate()
  const params = useParams({ strict: false })
  const currentDocumentId = (params as { documentId?: string }).documentId
  const { openDocuments, openDocument, setFocusedDocumentId } = useDocumentWorkspace()

  const openAndNavigate = useCallback(
    (doc: DocumentResponse) => {
      openDocument({
        id: doc.id,
        title: doc.title,
        workspaceId: doc.workspace_id,
      })
      navigate({
        to: '/document/$documentId',
        params: { documentId: doc.id },
      })
    },
    [navigate, openDocument]
  )

  const handleSelectDocument = useCallback(
    (doc: DocumentResponse) => {
      if (openDocuments.has(doc.id)) {
        setFocusedDocumentId(doc.id)
        navigate({
          to: '/document/$documentId',
          params: { documentId: doc.id },
        })
      } else {
        openAndNavigate(doc)
      }
    },
    [openDocuments, setFocusedDocumentId, navigate, openAndNavigate]
  )

  return (
    <div className="flex h-screen">
      <Sidebar
        currentWorkspaceId={effectiveWorkspaceId ?? undefined}
        currentDocumentId={currentDocumentId}
        onSelectWorkspace={onSelectWorkspace}
        onSelectDocument={handleSelectDocument}
        onOpenInNewTile={openAndNavigate}
        onCreateDocument={() => setCreateDialogOpen(true)}
        notificationSlot={notificationSlot}
        onSettingsClick={onSettingsClick}
      />
      <div className="flex-1 overflow-hidden">
        <Outlet />
      </div>
      {settingsSlot}
      {effectiveWorkspaceId && (
        <CreateDocumentDialog
          open={createDialogOpen}
          onOpenChange={setCreateDialogOpen}
          workspaceId={effectiveWorkspaceId}
          onCreated={onDocumentCreated}
        />
      )}
    </div>
  )
}
