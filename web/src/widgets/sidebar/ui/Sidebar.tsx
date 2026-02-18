import { FilePlus } from 'lucide-react'
import { DocumentTree } from './DocumentTree'
import { UserMenu } from './UserMenu'
import { Button } from '@/shared/ui/button'
import { useWorkspacesData } from '@/entities/workspace'
import { useDocumentsData } from '@/entities/document'
import type { DocumentResponse } from '@/shared/api'

interface SidebarProps {
  currentWorkspaceId: string | undefined
  currentDocumentId?: string
  onSelectWorkspace: (workspaceId: string) => void
  onSelectDocument: (doc: DocumentResponse) => void
  onOpenInNewTile?: (doc: DocumentResponse) => void
  onCreateDocument: () => void
  notificationSlot?: React.ReactNode
  onSettingsClick: () => void
}

export function Sidebar({
  currentWorkspaceId,
  currentDocumentId,
  onSelectWorkspace,
  onSelectDocument,
  onOpenInNewTile,
  onCreateDocument,
  notificationSlot,
  onSettingsClick,
}: SidebarProps) {
  const workspaces = useWorkspacesData() ?? []
  const documentsData = useDocumentsData()
  const documents = documentsData?.documents ?? []
  const documentsLoading = documentsData?.documentsLoading ?? false

  return (
    <aside className="w-64 border-r border-border h-full flex flex-col bg-sidebar">
      {/* Header */}
      {currentWorkspaceId && (
        <div className="px-2 py-1 border-b border-border flex items-center justify-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={onCreateDocument}
          >
            <FilePlus className="h-4 w-4" />
          </Button>
        </div>
      )}

      {/* Document Tree */}
      <div className="flex-1 overflow-hidden flex flex-col">
        <DocumentTree
          documents={documents}
          loading={documentsLoading}
          currentDocumentId={currentDocumentId}
          onSelectDocument={onSelectDocument}
          onOpenInNewTile={onOpenInNewTile}
        />
      </div>

      {/* User Menu with Workspace Switcher */}
      <UserMenu
        workspaces={workspaces}
        currentWorkspaceId={currentWorkspaceId}
        onSelectWorkspace={onSelectWorkspace}
        notificationSlot={notificationSlot}
        onSettingsClick={onSettingsClick}
      />
    </aside>
  )
}
