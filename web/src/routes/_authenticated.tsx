import { createFileRoute } from '@tanstack/react-router'
import { PdkFallbackDialog } from '@/features/auth'
import { WorkspaceSelectionProvider, WorkspacesDataContext } from '@/entities/workspace'
import { DocumentsDataContext } from '@/entities/document'
import { PendingDeviceProvider } from '@/features/device'
import { DocumentWorkspaceProvider } from '@/widgets/document-workspace'
import { NotificationList } from '@/widgets/notification'
import { SettingsDialog } from '@/widgets/settings'
import { AppShell } from './_authenticated/-components/AppShell'
import { useAuthenticatedLayout } from './_authenticated/-hooks/useAuthenticatedLayout'
import { Loader2 } from 'lucide-react'

function AuthenticatedLayoutInner() {
  const {
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
  } = useAuthenticatedLayout()

  return (
    <DocumentWorkspaceProvider>
      {pdkFallback && (
        <PdkFallbackDialog
          open={true}
          email={pdkFallback.email}
          onSubmit={handlePdkFallback}
          onCancel={handleDismissPdkFallback}
        />
      )}
      {isRestoring ? (
        <div className="flex h-screen items-center justify-center">
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            <p className="text-muted-foreground">Restoring session...</p>
          </div>
        </div>
      ) : !isAuthenticated ? null : (
        <WorkspacesDataContext.Provider value={workspaces}>
        <DocumentsDataContext.Provider value={{ documents, documentsLoading }}>
        <PendingDeviceProvider>
          <AppShell
            effectiveWorkspaceId={effectiveWorkspaceId}
            onSelectWorkspace={handleSelectWorkspace}
            createDialogOpen={createDialogOpen}
            setCreateDialogOpen={setCreateDialogOpen}
            onDocumentCreated={handleDocumentCreated}
            notificationSlot={<NotificationList />}
            settingsSlot={<SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />}
            onSettingsClick={() => setSettingsOpen(true)}
          />
        </PendingDeviceProvider>
        </DocumentsDataContext.Provider>
        </WorkspacesDataContext.Provider>
      )}
    </DocumentWorkspaceProvider>
  )
}

function AuthenticatedLayout() {
  return (
    <WorkspaceSelectionProvider>
      <AuthenticatedLayoutInner />
    </WorkspaceSelectionProvider>
  )
}

export const Route = createFileRoute('/_authenticated')({
  component: AuthenticatedLayout,
})
