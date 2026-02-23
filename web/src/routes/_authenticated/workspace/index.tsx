/**
 * Workspace Index (no ID)
 *
 * Resolves the default workspace and redirects.
 * Used when the user is authenticated but has no persisted workspace
 * (e.g. first login, cleared localStorage).
 * The _authenticated layout's useWorkspaces hook sets the default workspace
 * in the selection context, and this component navigates once it's available.
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { useWorkspaceSelection } from '@/entities/workspace'
import { CreateWorkspaceDialog } from '@/features/workspace-create'
import { Loader2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'

export const Route = createFileRoute('/_authenticated/workspace/')({
  component: WorkspaceResolver,
})

/** Timeout (ms) before showing the "no workspace" fallback UI. */
const RESOLVE_TIMEOUT_MS = 5000

function WorkspaceResolver() {
  const navigate = useNavigate()
  const { currentWorkspaceId } = useWorkspaceSelection()
  const [timedOut, setTimedOut] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)

  useEffect(() => {
    if (currentWorkspaceId) {
      navigate({
        to: '/workspace/$workspaceId',
        params: { workspaceId: currentWorkspaceId },
        replace: true,
      })
      return
    }

    const timer = setTimeout(() => setTimedOut(true), RESOLVE_TIMEOUT_MS)
    return () => clearTimeout(timer)
  }, [currentWorkspaceId, navigate])

  if (timedOut && !currentWorkspaceId) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-center">
          <p className="text-muted-foreground">
            No workspace found. Create one to get started.
          </p>
          <Button onClick={() => setCreateOpen(true)}>
            Create workspace
          </Button>
          <CreateWorkspaceDialog open={createOpen} onOpenChange={setCreateOpen} />
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="text-muted-foreground">Loading workspace...</p>
      </div>
    </div>
  )
}
