import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { workspaceApi } from '@/shared/api'

export interface UseWorkspacesResult {
  workspaces: ReturnType<typeof useWorkspacesInner>['workspaces']
  isFetched: boolean
}

function useWorkspacesInner(opts: {
  isAuthenticated: boolean
  isRestoring: boolean
}) {
  const { isAuthenticated, isRestoring } = opts

  const { data: workspaces = [], isFetched } = useQuery({
    queryKey: ['workspaces'],
    queryFn: async () => {
      const response = await workspaceApi.list()
      return response.workspaces
    },
    enabled: isAuthenticated && !isRestoring,
  })

  return { workspaces, isFetched }
}

export function useWorkspaces(opts: {
  isAuthenticated: boolean
  isRestoring: boolean
  effectiveWorkspaceId: string | null | undefined
  setCurrentWorkspaceId: (id: string) => void
}) {
  const { effectiveWorkspaceId, setCurrentWorkspaceId } = opts
  const { workspaces, isFetched } = useWorkspacesInner(opts)

  // Set default workspace when none is selected, or when the persisted
  // workspace is no longer accessible (e.g. user was removed from it).
  useEffect(() => {
    if (!isFetched || workspaces.length === 0) return

    const needsDefault =
      !effectiveWorkspaceId ||
      !workspaces.some((w) => w.workspace.id === effectiveWorkspaceId)

    if (needsDefault) {
      const defaultWs = workspaces.find((w) => w.membership.is_default)
      const wsId = defaultWs?.workspace.id ?? workspaces[0].workspace.id
      setCurrentWorkspaceId(wsId)
    }
  }, [workspaces, isFetched, effectiveWorkspaceId, setCurrentWorkspaceId])

  return { workspaces, isFetched }
}
