import { createFileRoute } from '@tanstack/react-router'

import { settingsRouteConfig } from '@/features/settings/config'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import GitSyncPage from '@/widgets/settings/GitSyncPage'

export const Route = createFileRoute('/(app)/settings/git-sync')({
  ...settingsRouteConfig,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: GitSyncPage,
})
