import { createFileRoute, redirect, useNavigate } from '@tanstack/react-router'

import { getSecurityStatus, me as fetchCurrentUser } from '@/entities/user'

import { RestorePrompt, UnlockPrompt, useKeyVault } from '@/features/security'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(auth)/auth/unlock' as any)({
  staticData: { layout: 'auth' },
  beforeLoad: async () => {
    // Must be authenticated to access unlock
    try {
      await fetchCurrentUser()
    } catch {
      throw redirect({
        to: '/auth/signin',
        search: { redirect: '/auth/unlock' },
      })
    }

    // Check if user has E2EE setup on server
    const status = await getSecurityStatus()
    if (!status.isSetupCompleted) {
      // No setup on server - redirect to setup wizard
      throw redirect({ to: '/auth/setup' })
    }

    return { serverSetupComplete: true }
  },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: UnlockRoute,
})

function UnlockRoute() {
  const navigate = useNavigate()
  const { isUnlocked, loading, isInitialized, hasLocalKeys, needsRestore } = useKeyVault()

  // Wait for E2EE context to initialize
  if (!isInitialized || loading || hasLocalKeys === null) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-4">
        <RoutePending />
      </div>
    )
  }

  // Already unlocked - redirect to dashboard
  if (isUnlocked) {
    navigate({ to: '/dashboard' })
    return null
  }

  // Local keys exist but not unlocked - show unlock prompt (page reload scenario)
  if (hasLocalKeys && !isUnlocked) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-4">
        <UnlockPrompt onUnlocked={() => navigate({ to: '/dashboard' })} />
      </div>
    )
  }

  // No local keys - need to restore from server (new device scenario)
  if (!hasLocalKeys && needsRestore) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-4">
        <RestorePrompt onRestored={() => navigate({ to: '/dashboard' })} />
      </div>
    )
  }

  // Fallback - show restore prompt
  return (
    <div className="min-h-screen flex items-center justify-center py-12 px-4">
      <RestorePrompt onRestored={() => navigate({ to: '/dashboard' })} />
    </div>
  )
}
