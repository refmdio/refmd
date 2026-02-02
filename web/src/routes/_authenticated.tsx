import { useState, useEffect, useCallback } from 'react'
import { Outlet, createFileRoute, redirect, useNavigate, useParams } from '@tanstack/react-router'
import { authApi, workspaceApi, documentApi, ApiRequestError, ApiError } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import { Sidebar } from '@/widgets/sidebar'
import { CreateDocumentDialog } from '@/features/document-create'
import type { components } from '@/shared/api'

type WorkspaceWithMembership = components['schemas']['WorkspaceWithMembershipResponse']
type DocumentResponse = components['schemas']['DocumentResponse']

export const Route = createFileRoute('/_authenticated')({
  beforeLoad: async () => {
    // Skip auth check during SSR (no cookies available on server)
    if (typeof window === 'undefined') {
      return
    }

    try {
      await authApi.me()
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        throw redirect({ to: '/auth/login' })
      }
      throw error
    }
  },
  component: AuthenticatedLayout,
})

function AuthenticatedLayout() {
  const navigate = useNavigate()
  const params = useParams({ strict: false })
  const { currentWorkspaceId, setCurrentWorkspaceId } = useAuthContext()

  const [workspaces, setWorkspaces] = useState<WorkspaceWithMembership[]>([])
  const [documents, setDocuments] = useState<DocumentResponse[]>([])
  const [documentsLoading, setDocumentsLoading] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)

  // Get workspaceId from URL params if available
  const urlWorkspaceId = params.workspaceId as string | undefined

  // Effective workspace ID (URL > context > default)
  const effectiveWorkspaceId = urlWorkspaceId ?? currentWorkspaceId

  // Fetch workspaces on mount
  useEffect(() => {
    async function fetchWorkspaces() {
      try {
        const response = await workspaceApi.list()
        setWorkspaces(response.workspaces)

        // Set default workspace if none selected
        if (!effectiveWorkspaceId && response.workspaces.length > 0) {
          const defaultWs = response.workspaces.find((w) => w.membership.is_default)
          const wsId = defaultWs?.workspace.id ?? response.workspaces[0].workspace.id
          setCurrentWorkspaceId(wsId)
        }
      } catch (err) {
        console.error('Failed to fetch workspaces:', err)
      }
    }

    fetchWorkspaces()
  }, [effectiveWorkspaceId, setCurrentWorkspaceId])

  // Fetch documents when workspace changes
  useEffect(() => {
    if (!effectiveWorkspaceId) {
      setDocuments([])
      return
    }

    async function fetchDocuments() {
      setDocumentsLoading(true)
      try {
        const response = await documentApi.list(effectiveWorkspaceId!, { rootOnly: false })
        setDocuments(response.documents)
      } catch (err) {
        if (err instanceof ApiError) {
          console.error('Failed to fetch documents:', err.message)
        }
        setDocuments([])
      } finally {
        setDocumentsLoading(false)
      }
    }

    fetchDocuments()
  }, [effectiveWorkspaceId])

  const handleSelectWorkspace = useCallback(
    (workspaceId: string) => {
      setCurrentWorkspaceId(workspaceId)
      navigate({ to: '/workspace/$workspaceId', params: { workspaceId } })
    },
    [navigate, setCurrentWorkspaceId]
  )

  const handleDocumentCreated = useCallback((doc: DocumentResponse) => {
    setDocuments((prev) => [doc, ...prev])
  }, [])

  return (
    <div className="flex h-screen">
      <Sidebar
        workspaces={workspaces}
        currentWorkspaceId={effectiveWorkspaceId ?? undefined}
        documents={documents}
        documentsLoading={documentsLoading}
        onSelectWorkspace={handleSelectWorkspace}
        onCreateDocument={() => setCreateDialogOpen(true)}
      />
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
      {effectiveWorkspaceId && (
        <CreateDocumentDialog
          open={createDialogOpen}
          onOpenChange={setCreateDialogOpen}
          workspaceId={effectiveWorkspaceId}
          onCreated={handleDocumentCreated}
        />
      )}
    </div>
  )
}
