import { WorkspaceCard, useWorkspacesData } from '@/entities/workspace'
import { LoadingPlaceholder } from '@/shared/ui/loading-placeholder'

export function WorkspaceList() {
  const workspaces = useWorkspacesData()

  if (!workspaces) {
    return (
      <LoadingPlaceholder>Loading workspaces...</LoadingPlaceholder>
    )
  }

  return (
    <div className="space-y-4">
      {workspaces.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          No workspaces found. Create one from Settings.
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {workspaces.map((ws) => (
            <WorkspaceCard key={ws.workspace.id} data={ws} />
          ))}
        </div>
      )}
    </div>
  )
}
