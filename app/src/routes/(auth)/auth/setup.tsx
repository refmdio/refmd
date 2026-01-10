import { createFileRoute, redirect, useNavigate } from '@tanstack/react-router'

import { getSecurityStatus, me as fetchCurrentUser } from '@/entities/user'

import { SecuritySetupWizard, RestorePrompt, UnlockPrompt, useE2EE } from '@/features/e2ee'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

// Route path type will be generated after first build
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const Route = createFileRoute('/(auth)/auth/setup' as any)({
  staticData: { layout: 'auth' },
  beforeLoad: async () => {
    // Must be authenticated to access setup
    try {
      await fetchCurrentUser()
    } catch {
      throw redirect({
        to: '/auth/signin',
        search: { redirect: '/auth/setup' },
      })
    }

    // Check if user already has E2EE setup on server
    // Note: Local key check happens in component (client-side only)
    const status = await getSecurityStatus()
    if (status.isSetupCompleted) {
      // Server has setup, but client might need restore
      // Let the component handle this
      return { serverSetupComplete: true }
    }
    return { serverSetupComplete: false }
  },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SecuritySetupRoute,
})

function SecuritySetupRoute() {
  const navigate = useNavigate()
  const { needsRestore, isUnlocked, loading, isInitialized, hasLocalKeys } = useE2EE()
  const loaderData = Route.useLoaderData()
  const serverSetupComplete = loaderData?.serverSetupComplete ?? false

  // Wait for E2EE context to initialize and local key check to complete
  if (!isInitialized || loading || hasLocalKeys === null) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-4">
        <RoutePending />
      </div>
    )
  }

  // If already unlocked AND server setup is complete, redirect to dashboard
  // Note: Don't redirect during initial setup flow (serverSetupComplete === false)
  // because the wizard needs to show recovery key even after keys are unlocked
  if (isUnlocked && serverSetupComplete) {
    navigate({ to: '/dashboard' })
    return null
  }

  // Server has setup complete, local keys exist, but not unlocked - show unlock prompt
  // This happens after page reload when UMK is cleared from memory
  if (serverSetupComplete && hasLocalKeys && !isUnlocked) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-4">
        <UnlockPrompt onUnlocked={() => navigate({ to: '/dashboard' })} />
      </div>
    )
  }

  // Server has setup complete but no local keys - need to restore from server
  if (serverSetupComplete && !hasLocalKeys && needsRestore) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-4">
        <RestorePrompt onRestored={() => navigate({ to: '/dashboard' })} />
      </div>
    )
  }

  // No setup on server - show setup wizard
  // The wizard handles its own completion and navigation
  return (
    <div className="min-h-screen flex items-center justify-center py-12 px-4">
      <SecuritySetupWizard />
    </div>
  )
}
