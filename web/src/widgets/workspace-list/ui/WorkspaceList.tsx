import { useState, useEffect } from 'react'
import { workspaceApi, ApiError } from '@/shared/api'
import { WorkspaceCard } from '@/entities/workspace/ui/WorkspaceCard'
import type { components } from '@/shared/api'

type WorkspaceWithMembership = components['schemas']['WorkspaceWithMembershipResponse']

export function WorkspaceList() {
  const [workspaces, setWorkspaces] = useState<WorkspaceWithMembership[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchWorkspaces() {
      try {
        const response = await workspaceApi.list()
        setWorkspaces(response.workspaces)
      } catch (err) {
        if (err instanceof ApiError) {
          setError(err.message)
        } else {
          setError('Failed to load workspaces')
        }
      } finally {
        setLoading(false)
      }
    }

    fetchWorkspaces()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-muted-foreground">Loading workspaces...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-4 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
        {error}
      </div>
    )
  }

  if (workspaces.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        No workspaces found
      </div>
    )
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      {workspaces.map((ws) => (
        <WorkspaceCard key={ws.workspace.id} data={ws} />
      ))}
    </div>
  )
}
