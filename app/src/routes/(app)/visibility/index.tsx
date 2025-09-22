import { createFileRoute } from '@tanstack/react-router'

import { queryClient } from '@/shared/lib/queryClient'

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
  loader: async () => {
    await queryClient.ensureQueryData(activeSharesQuery())
    return null
  },
  component: VisibilityPage,
})
