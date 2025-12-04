import { createFileRoute } from '@tanstack/react-router'

import { settingsRouteConfig } from '@/features/settings/config'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import SettingsView from '@/widgets/settings/SettingsView'

export const Route = createFileRoute('/(app)/settings')({
  ...settingsRouteConfig,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SettingsView,
})
