import { useState } from 'react'
import { Settings, ChevronsUpDown, Check } from 'lucide-react'
import { NotificationList } from '@/widgets/notification'
import { SettingsDialog } from '@/widgets/settings'
import { Button } from '@/shared/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'
import type { components } from '@/shared/api'

type WorkspaceWithMembership = components['schemas']['WorkspaceWithMembershipResponse']

interface UserMenuProps {
  workspaces: WorkspaceWithMembership[]
  currentWorkspaceId: string | undefined
  onSelectWorkspace: (workspaceId: string) => void
}

export function UserMenu({ workspaces, currentWorkspaceId, onSelectWorkspace }: UserMenuProps) {
  const [settingsOpen, setSettingsOpen] = useState(false)

  const currentWorkspace = workspaces.find((w) => w.workspace.id === currentWorkspaceId)

  const formatWorkspaceName = (name: string) => name.replace(/'s workspace$/i, '')
  const displayName = currentWorkspace?.workspace.name
    ? formatWorkspaceName(currentWorkspace.workspace.name)
    : 'Select workspace'

  return (
    <div className="border-t border-border px-2 py-1">
      <div className="flex items-center gap-1">
        {/* Workspace Switcher */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              className="flex-1 justify-start px-3 py-2 h-auto font-sans normal-case tracking-normal text-xs"
            >
              <span className="flex items-center gap-2">
                <ChevronsUpDown className="h-4 w-4 shrink-0 opacity-50" />
                <span className="truncate font-bold">{displayName}</span>
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent side="top" align="start" className="w-56">
            {workspaces.map((ws) => (
              <DropdownMenuItem
                key={ws.workspace.id}
                onClick={() => onSelectWorkspace(ws.workspace.id)}
                className="font-sans text-sm normal-case tracking-normal"
              >
                <span className="flex-1 truncate">{formatWorkspaceName(ws.workspace.name)}</span>
                {ws.workspace.id === currentWorkspaceId && (
                  <Check className="h-4 w-4 shrink-0" />
                )}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Notification List */}
        <NotificationList />

        {/* Settings Button */}
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9"
          onClick={() => setSettingsOpen(true)}
        >
          <Settings className="h-4 w-4" />
        </Button>
      </div>

      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
    </div>
  )
}
