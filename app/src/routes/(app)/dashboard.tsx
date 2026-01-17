import { createFileRoute } from '@tanstack/react-router'

import { listDocumentsQuery } from '@/entities/document'
import { meQuery } from '@/entities/user'

import { requireAuthGuard } from '@/features/auth'
import { RequireKeyVault } from '@/features/security'

import DashboardPage from '@/widgets/dashboard/DashboardPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

function DashboardRoute() {
  return (
    <RequireKeyVault>
      <DashboardPage />
    </RequireKeyVault>
  )
}

export const Route = createFileRoute('/(app)/dashboard')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending label="Loading dashboard…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: requireAuthGuard,
  loader: async ({ context }) => {
    const me = await context.queryClient.ensureQueryData(meQuery())
    const workspaceId = me?.active_workspace_id ?? null
    await context.queryClient.ensureQueryData(listDocumentsQuery({ workspaceId }))
    return null
  },
  component: DashboardRoute,
})
