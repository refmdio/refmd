import { useState, useEffect, useCallback, useRef } from 'react'
import { Outlet, createFileRoute, useNavigate, useParams } from '@tanstack/react-router'
import { workspaceApi, documentApi, ApiError } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import { restoreSession, restoreSessionWithPdk } from '@/features/auth'
import type { PdkFallbackRequired } from '@/features/auth'
import { loadDeviceId, loadDsk, loadAndUnwrapDeviceKeys } from '@/shared/lib/crypto'
import { setPopCredentials } from '@/shared/lib/pop-store'
import { PendingDeviceProvider } from '@/features/device'
import { PdkFallbackDialog } from '@/features/auth/PdkFallbackDialog'
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
  const { auth, setAuthState, setDeviceState, currentWorkspaceId, setCurrentWorkspaceId } = useAuthContext()

  const [isRestoring, setIsRestoring] = useState(!auth) // Need restoration if no auth
  const [pdkFallback, setPdkFallback] = useState<PdkFallbackRequired | null>(null)
  const [workspaces, setWorkspaces] = useState<WorkspaceWithMembership[]>([])
  const [documents, setDocuments] = useState<DocumentResponse[]>([])
  const [documentsLoading, setDocumentsLoading] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)

  // Track if restoration has been attempted to prevent re-running on auth change
  const restorationAttempted = useRef(false)

  // Get workspaceId from URL params if available
  const urlWorkspaceId = params.workspaceId as string | undefined

  // Effective workspace ID (URL > context > default)
  const effectiveWorkspaceId = urlWorkspaceId ?? currentWorkspaceId

  // Restore session from IndexedDB if not already authenticated
  useEffect(() => {
    // If already authenticated (e.g., from login page), skip restoration
    if (auth && !restorationAttempted.current) {
      setIsRestoring(false)
      return
    }

    // If restoration already attempted, don't re-run
    // This prevents the effect from re-running when setAuthState triggers a re-render
    if (restorationAttempted.current) {
      return
    }

    restorationAttempted.current = true

    async function tryRestoreSession() {
      try {
        const result = await restoreSession()

        // Handle PDK fallback required
        if (result && 'type' in result && result.type === 'pdk_fallback_required') {
          setPdkFallback(result)
          setIsRestoring(false)
          return
        }

        if (result && !('type' in result)) {
          // Also restore device keys for PoP authentication FIRST
          // This must happen before setAuthState to ensure PoP credentials
          // are available when child components make API calls
          const deviceId = await loadDeviceId()
          if (deviceId) {
            const dsk = await loadDsk()
            if (dsk) {
              const deviceKeysData = await loadAndUnwrapDeviceKeys(dsk)
              if (deviceKeysData && deviceKeysData.userId === result.userId) {
                // Set PoP credentials synchronously before any state updates
                setPopCredentials(deviceId, deviceKeysData.signingPrivateKey)

                setDeviceState({
                  deviceId,
                  deviceKeys: {
                    ecdhPrivateKey: deviceKeysData.ecdhPrivateKey,
                    ecdhPublicKey: deviceKeysData.ecdhPublicKey,
                    signingPrivateKey: deviceKeysData.signingPrivateKey,
                    signingPublicKey: deviceKeysData.signingPublicKey,
                  },
                })
              }
            }
          }

          // Session restored successfully - set auth state AFTER device keys
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
  }, [auth, setAuthState, setDeviceState, navigate])

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

  // PDK fallback handler: user re-enters password to derive PDK and unwrap keys
  const handlePdkFallback = useCallback(async (password: string) => {
    if (!pdkFallback) return

    const result = await restoreSessionWithPdk(pdkFallback.email, password)
    if (!result) {
      throw new Error('Failed to restore session. Please check your password.')
    }

    // Set PoP credentials from PDK-unwrapped device keys
    // deviceId comes from server (meResponse.device_id), so it's always reliable
    setPopCredentials(result.deviceId, result.deviceKeys.signingPrivateKey)
    setDeviceState({
      deviceId: result.deviceId,
      deviceKeys: result.deviceKeys,
    })

    setPdkFallback(null)
    setAuthState({
      userId: result.userId,
      email: result.email,
      umk: result.umk,
      identityKeys: result.identityKeys,
      expiresAt: result.expiresAt,
    })
  }, [pdkFallback, setAuthState, setDeviceState])

  // Always wrap in DocumentWorkspaceProvider to ensure context is available
  // for child routes that may render during navigation
  return (
    <DocumentWorkspaceProvider>
      {pdkFallback && (
        <PdkFallbackDialog
          open={true}
          email={pdkFallback.email}
          onSubmit={handlePdkFallback}
          onCancel={() => {
            setPdkFallback(null)
            navigate({ to: '/auth/login' })
          }}
        />
      )}
      {isRestoring ? (
        <div className="flex h-screen items-center justify-center">
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            <p className="text-muted-foreground">Restoring session...</p>
          </div>
        </div>
      ) : !auth ? null : (
        <PendingDeviceProvider>
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
        </PendingDeviceProvider>
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
