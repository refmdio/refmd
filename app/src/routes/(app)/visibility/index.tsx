import { createFileRoute } from '@tanstack/react-router'

import { activeSharesQuery } from '@/entities/share'

import { appBeforeLoadGuard } from '@/features/auth'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import VisibilityPage from '@/widgets/visibility/VisibilityPage'

export const Route = createFileRoute('/(app)/visibility/')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: appBeforeLoadGuard,
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(activeSharesQuery())
    return null
  },
  component: VisibilityPage,
})
