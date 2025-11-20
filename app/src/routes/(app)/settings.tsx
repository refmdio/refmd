import { createFileRoute } from '@tanstack/react-router'

import { requireAuthGuard } from '@/features/auth'


import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import SettingsView from '@/widgets/settings/SettingsView'

export const Route = createFileRoute('/(app)/settings')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: requireAuthGuard,
  component: SettingsView,
})
