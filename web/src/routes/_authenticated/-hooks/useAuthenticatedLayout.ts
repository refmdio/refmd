import { useState, useCallback, useEffect } from 'react'
import { useNavigate, useParams } from '@tanstack/react-router'
import { useAuthContext } from '@/shared/context'
import { useSessionRestore } from '@/features/auth'
import { useWorkspaces, useWorkspaceSelection } from '@/entities/workspace'
import { useDocuments } from '@/entities/document'

export function useAuthenticatedLayout() {
  const navigate = useNavigate()
  const params = useParams({ strict: false })
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
  const effectiveWorkspaceId = urlWorkspaceId ?? currentWorkspaceId

  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  const workspaces = useWorkspaces({
    isAuthenticated,
    isRestoring,
    effectiveWorkspaceId,
    setCurrentWorkspaceId,
  })

  const { documents, documentsLoading, addDocument: handleDocumentCreated } = useDocuments({
    isAuthenticated,
    isRestoring,
    workspaceId: effectiveWorkspaceId,
  })

  const handleSelectWorkspace = useCallback(
    (workspaceId: string) => {
      setCurrentWorkspaceId(workspaceId)
      navigate({ to: '/workspace/$workspaceId', params: { workspaceId } })
    },
    [navigate, setCurrentWorkspaceId]
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
