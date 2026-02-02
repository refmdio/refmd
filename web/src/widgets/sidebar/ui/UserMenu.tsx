import { useNavigate } from '@tanstack/react-router'
import { Settings, ChevronsUpDown, Check, LogOut, Moon, Sun } from 'lucide-react'
import { useAuthContext } from '@/shared/context/AuthContext'
import { useTheme } from '@/shared/context/ThemeContext'
import { logout } from '@/features/auth'
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
  const { clearAuthState } = useAuthContext()
  const { isDarkMode, toggleTheme } = useTheme()
  const navigate = useNavigate()

  const currentWorkspace = workspaces.find((w) => w.workspace.id === currentWorkspaceId)

  const formatWorkspaceName = (name: string) => name.replace(/'s workspace$/i, '')
  const displayName = currentWorkspace?.workspace.name
    ? formatWorkspaceName(currentWorkspace.workspace.name)
    : 'Select workspace'

  const handleLogout = async () => {
    try {
      await logout()
    } catch {
      // Ignore errors
    } finally {
      clearAuthState()
      navigate({ to: '/auth/login' })
    }
  }

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

        {/* Settings Button */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-9 w-9">
              <Settings className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent side="top" align="end">
            <DropdownMenuItem onClick={toggleTheme}>
              {isDarkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              <span>{isDarkMode ? 'Light mode' : 'Dark mode'}</span>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={handleLogout}>
              <LogOut className="h-4 w-4" />
              <span>Logout</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )
}
