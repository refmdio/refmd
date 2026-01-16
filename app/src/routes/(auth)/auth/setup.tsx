import { createFileRoute, redirect } from '@tanstack/react-router'

import { getSecurityStatus, me as fetchCurrentUser } from '@/entities/user'

import { SecuritySetupWizard } from '@/features/security'

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
    const status = await getSecurityStatus()
    if (status.isSetupCompleted) {
      // Already set up - redirect to unlock page for key restoration/unlock
      throw redirect({ to: '/auth/unlock' })
    }

    return {}
  },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SecuritySetupRoute,
})

/**
 * Setup route - only for new users who haven't completed E2EE setup
 */
function SecuritySetupRoute() {
  return (
    <div className="min-h-screen flex items-center justify-center py-12 px-4">
      <SecuritySetupWizard />
    </div>
  )
}
