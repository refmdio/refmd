import { createFileRoute } from '@tanstack/react-router'

import { settingsRouteConfig } from '@/features/settings/config'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import ShortcutsPage from '@/widgets/settings/ShortcutsPage'

export const Route = createFileRoute('/(app)/settings/shortcuts')({
  ...settingsRouteConfig,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: ShortcutsPage,
})
