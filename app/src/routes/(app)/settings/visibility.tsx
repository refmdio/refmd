import { createFileRoute } from '@tanstack/react-router'

import { activeSharesQuery } from '@/entities/share'

import { settingsRouteConfig } from '@/features/settings/config'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import VisibilityPage from '@/widgets/visibility/VisibilityPage'

export const Route = createFileRoute('/(app)/settings/visibility')({
  ...settingsRouteConfig,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(activeSharesQuery())
    return null
  },
  component: VisibilityPage,
})
