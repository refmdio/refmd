import { FilePlus, FolderPlus } from 'lucide-react'
import { DocumentTree } from './DocumentTree'
import { UserMenu } from './UserMenu'
import { Button } from '@/shared/ui/button'
import type { components } from '@/shared/api'

type WorkspaceWithMembership = components['schemas']['WorkspaceWithMembershipResponse']
type DocumentResponse = components['schemas']['DocumentResponse']

interface SidebarProps {
  workspaces: WorkspaceWithMembership[]
  currentWorkspaceId: string | undefined
  documents: DocumentResponse[]
  documentsLoading?: boolean
  onSelectWorkspace: (workspaceId: string) => void
  onCreateDocument: () => void
  onCreateFolder?: () => void
}

export function Sidebar({
  workspaces,
  currentWorkspaceId,
  documents,
  documentsLoading,
  onSelectWorkspace,
  onCreateDocument,
  onCreateFolder,
}: SidebarProps) {
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
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={onCreateFolder}
          >
            <FolderPlus className="h-4 w-4" />
          </Button>
        </div>
      )}

      {/* Document Tree */}
      <div className="flex-1 overflow-hidden flex flex-col">
        <DocumentTree documents={documents} loading={documentsLoading} />
      </div>

      {/* User Menu with Workspace Switcher */}
      <UserMenu
        workspaces={workspaces}
        currentWorkspaceId={currentWorkspaceId}
        onSelectWorkspace={onSelectWorkspace}
      />
    </aside>
  )
}
