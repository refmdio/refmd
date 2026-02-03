import { useState, useEffect, useCallback } from 'react'
import { Outlet, createFileRoute, useNavigate, useParams } from '@tanstack/react-router'
import { workspaceApi, documentApi, ApiError } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import { restoreSession } from '@/features/auth'
import { Sidebar } from '@/widgets/sidebar'
import { CreateDocumentDialog } from '@/features/document-create'
import {
  DocumentWorkspaceProvider,
  useDocumentWorkspace,
} from '@/widgets/document-workspace'
import { Loader2 } from 'lucide-react'
import type { components } from '@/shared/api'

type WorkspaceWithMembership = components['schemas']['WorkspaceWithMembershipResponse']
type DocumentResponse = components['schemas']['DocumentResponse']

export const Route = createFileRoute('/_authenticated')({
  component: AuthenticatedLayout,
})

function AuthenticatedLayout() {
  const navigate = useNavigate()
  const params = useParams({ strict: false })
  const { auth, setAuthState, currentWorkspaceId, setCurrentWorkspaceId } = useAuthContext()

  const [isRestoring, setIsRestoring] = useState(!auth) // Need restoration if no auth
  const [workspaces, setWorkspaces] = useState<WorkspaceWithMembership[]>([])
  const [documents, setDocuments] = useState<DocumentResponse[]>([])
  const [documentsLoading, setDocumentsLoading] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)

  // Get workspaceId from URL params if available
  const urlWorkspaceId = params.workspaceId as string | undefined

  // Effective workspace ID (URL > context > default)
  const effectiveWorkspaceId = urlWorkspaceId ?? currentWorkspaceId

  // Restore session from IndexedDB if not already authenticated
  useEffect(() => {
    if (auth) {
      // Already authenticated (from login)
      setIsRestoring(false)
      return
    }

    async function tryRestoreSession() {
      try {
        const result = await restoreSession()
        if (result) {
          // Session restored successfully
          setAuthState({
            userId: result.userId,
            email: result.email,
            umk: result.umk,
            identityKeys: result.identityKeys,
            expiresAt: result.expiresAt,
          })
        } else {
          // No cached session or restoration failed
          navigate({ to: '/auth/login' })
        }
      } catch (err) {
        console.error('Session restoration failed:', err)
        navigate({ to: '/auth/login' })
      } finally {
        setIsRestoring(false)
      }
    }

    tryRestoreSession()
  }, [auth, setAuthState, navigate])

  // Fetch workspaces on mount (only when authenticated)
  useEffect(() => {
    if (!auth || isRestoring) {
      return
    }

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
  }, [auth, isRestoring, effectiveWorkspaceId, setCurrentWorkspaceId])

  // Fetch documents when workspace changes (only when authenticated)
  useEffect(() => {
    if (!auth || isRestoring || !effectiveWorkspaceId) {
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
  }, [auth, isRestoring, effectiveWorkspaceId])

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

  // Always wrap in DocumentWorkspaceProvider to ensure context is available
  // for child routes that may render during navigation
  return (
    <DocumentWorkspaceProvider>
      {isRestoring ? (
        <div className="flex h-screen items-center justify-center">
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            <p className="text-muted-foreground">Restoring session...</p>
          </div>
        </div>
      ) : !auth ? null : (
        <AuthenticatedLayoutInner
          workspaces={workspaces}
          documents={documents}
          documentsLoading={documentsLoading}
          effectiveWorkspaceId={effectiveWorkspaceId}
          onSelectWorkspace={handleSelectWorkspace}
          createDialogOpen={createDialogOpen}
          setCreateDialogOpen={setCreateDialogOpen}
          onDocumentCreated={handleDocumentCreated}
        />
      )}
    </DocumentWorkspaceProvider>
  )
}

interface AuthenticatedLayoutInnerProps {
  workspaces: WorkspaceWithMembership[]
  documents: DocumentResponse[]
  documentsLoading: boolean
  effectiveWorkspaceId: string | null | undefined
  onSelectWorkspace: (workspaceId: string) => void
  createDialogOpen: boolean
  setCreateDialogOpen: (open: boolean) => void
  onDocumentCreated: (doc: DocumentResponse) => void
}

function AuthenticatedLayoutInner({
  workspaces,
  documents,
  documentsLoading,
  effectiveWorkspaceId,
  onSelectWorkspace,
  createDialogOpen,
  setCreateDialogOpen,
  onDocumentCreated,
}: AuthenticatedLayoutInnerProps) {
  const navigate = useNavigate()
  const { openDocuments, openDocument, setFocusedDocumentId } = useDocumentWorkspace()

  const handleSelectDocument = useCallback(
    (doc: DocumentResponse) => {
      if (openDocuments.has(doc.id)) {
        setFocusedDocumentId(doc.id)
      } else {
        openDocument({
          id: doc.id,
          title: doc.title,
          workspaceId: doc.workspace_id,
        })
      }

      navigate({
        to: '/document/$documentId',
        params: { documentId: doc.id },
      })
    },
    [navigate, openDocuments, openDocument, setFocusedDocumentId]
  )

  const handleOpenInNewTile = useCallback(
    (doc: DocumentResponse) => {
      // Always open a new tile, even if document is already open
      openDocument({
        id: doc.id,
        title: doc.title,
        workspaceId: doc.workspace_id,
      })

      navigate({
        to: '/document/$documentId',
        params: { documentId: doc.id },
      })
    },
    [navigate, openDocument]
  )

  return (
    <div className="flex h-screen">
      <Sidebar
        workspaces={workspaces}
        currentWorkspaceId={effectiveWorkspaceId ?? undefined}
        documents={documents}
        documentsLoading={documentsLoading}
        onSelectWorkspace={onSelectWorkspace}
        onSelectDocument={handleSelectDocument}
        onOpenInNewTile={handleOpenInNewTile}
        onCreateDocument={() => setCreateDialogOpen(true)}
      />
      <div className="flex-1 overflow-hidden">
        <Outlet />
      </div>
      {effectiveWorkspaceId && (
        <CreateDocumentDialog
          open={createDialogOpen}
          onOpenChange={setCreateDialogOpen}
          workspaceId={effectiveWorkspaceId}
          onCreated={onDocumentCreated}
        />
      )}
    </div>
  )
}
