import { createFileRoute } from '@tanstack/react-router'

import { appBeforeLoadGuard } from '@/features/auth'
import SettingsView from '@/features/settings/layout/SettingsView'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(app)/settings')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: appBeforeLoadGuard,
  component: SettingsView,
})
