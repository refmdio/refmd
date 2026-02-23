import { useState, useCallback, useEffect } from 'react'
import { useNavigate, useParams, useRouterState } from '@tanstack/react-router'
import { useQueryClient } from '@tanstack/react-query'
import { useAuthContext } from '@/shared/context'
import { useSessionRestore } from '@/features/auth'
import { useWorkspaces, useWorkspaceSelection } from '@/entities/workspace'
import { useDocuments } from '@/entities/document'

export function useAuthenticatedLayout() {
  const navigate = useNavigate()
  const params = useParams({ strict: false })
  const routerState = useRouterState()
  const queryClient = useQueryClient()
  const { isAuthenticated } = useAuthContext()
  const { currentWorkspaceId, setCurrentWorkspaceId } = useWorkspaceSelection()

  const { isRestoring, pdkFallback, handlePdkFallback, dismissPdkFallback } =
    useSessionRestore()

  // Single redirect guard: if restoration completed and not authenticated, go to login
  useEffect(() => {
    if (!isRestoring && !isAuthenticated && !pdkFallback) {
      navigate({ to: '/auth/login' })
    }
  }, [isRestoring, isAuthenticated, pdkFallback, navigate])

  const urlWorkspaceId = (params as { workspaceId?: string }).workspaceId
  // URL takes priority for workspace resolution. currentWorkspaceId is the fallback
  // for routes without workspaceId in URL (e.g. /document/{id}).
  const effectiveWorkspaceId = urlWorkspaceId ?? currentWorkspaceId

  const currentPath = routerState.location.pathname

  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  const { workspaces, isFetched: workspacesFetched } = useWorkspaces({
    isAuthenticated,
    isRestoring,
    effectiveWorkspaceId,
    setCurrentWorkspaceId,
  })

  // Sync currentWorkspaceId (localStorage) from URL when URL changes.
  // Only sync if the workspace actually exists in the user's workspace list,
  // preventing stale/invalid IDs from being persisted.
  useEffect(() => {
    if (!urlWorkspaceId || urlWorkspaceId === currentWorkspaceId) return
    // Wait until the query has completed (distinguishes "not yet loaded" from "loaded 0")
    if (!workspacesFetched) return
    const isValid = workspaces.some((w) => w.workspace.id === urlWorkspaceId)
    if (isValid) {
      setCurrentWorkspaceId(urlWorkspaceId)
    } else {
      // URL contains an invalid workspace ID — redirect to workspace resolver
      // which will pick the default workspace
      setCurrentWorkspaceId(null)
      navigate({ to: '/workspace', replace: true })
    }
  }, [urlWorkspaceId, workspaces, workspacesFetched, currentWorkspaceId, setCurrentWorkspaceId, navigate])

  // Default redirect: when authenticated but on root "/", redirect to workspace.
  useEffect(() => {
    if (isRestoring || !isAuthenticated) return
    if (currentPath !== '/' && currentPath !== '') return
    if (!effectiveWorkspaceId) return
    navigate({ to: '/workspace/$workspaceId', params: { workspaceId: effectiveWorkspaceId }, replace: true })
  }, [isRestoring, isAuthenticated, currentPath, effectiveWorkspaceId, navigate])

  const { documents, documentsLoading, addDocument: handleDocumentCreated } = useDocuments({
    isAuthenticated,
    isRestoring,
    workspaceId: effectiveWorkspaceId,
  })

  const handleSelectWorkspace = useCallback(
    (workspaceId: string) => {
      queryClient.removeQueries({ queryKey: ['documents'] })
      // Navigate ONLY — do NOT call setCurrentWorkspaceId here.
      // The URL sync effect will update currentWorkspaceId AFTER the route changes.
      // This ensures the document page unmounts (leaving /document/$old) BEFORE
      // the Provider key changes, preventing the old document's useEffect from
      // re-opening it in the new Provider.
      navigate({ to: '/workspace/$workspaceId', params: { workspaceId } })
    },
    [navigate, queryClient]
  )

  // Dismissing PDK fallback sets pdkFallback=null; the redirect guard above handles navigation
  const handleDismissPdkFallback = useCallback(() => {
    dismissPdkFallback()
  }, [dismissPdkFallback])

  return {
    isAuthenticated,
    isRestoring,
    pdkFallback,
    handlePdkFallback,
    handleDismissPdkFallback,
    workspaces,
    documents,
    documentsLoading,
    effectiveWorkspaceId,
    handleSelectWorkspace,
    handleDocumentCreated,
    createDialogOpen,
    setCreateDialogOpen,
    settingsOpen,
    setSettingsOpen,
  }
}
