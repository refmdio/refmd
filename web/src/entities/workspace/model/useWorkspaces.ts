import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { workspaceApi } from '@/shared/api'

export function useWorkspaces(opts: {
  isAuthenticated: boolean
  isRestoring: boolean
  effectiveWorkspaceId: string | null | undefined
  setCurrentWorkspaceId: (id: string) => void
}) {
  const { isAuthenticated, isRestoring, effectiveWorkspaceId, setCurrentWorkspaceId } = opts

  const { data: workspaces = [] } = useQuery({
    queryKey: ['workspaces'],
    queryFn: async () => {
      const response = await workspaceApi.list()
      return response.workspaces
    },
    enabled: isAuthenticated && !isRestoring,
  })

  // Set default workspace when none is selected
  useEffect(() => {
    if (!effectiveWorkspaceId && workspaces.length > 0) {
      const defaultWs = workspaces.find((w) => w.membership.is_default)
      const wsId = defaultWs?.workspace.id ?? workspaces[0].workspace.id
      setCurrentWorkspaceId(wsId)
    }
  }, [workspaces, effectiveWorkspaceId, setCurrentWorkspaceId])

  return workspaces
}
