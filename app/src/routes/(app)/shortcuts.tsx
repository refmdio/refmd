import { createFileRoute } from '@tanstack/react-router'

import { requireAuthGuard } from '@/features/auth'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import ShortcutsPage from '@/widgets/settings/ShortcutsPage'

export const Route = createFileRoute('/(app)/shortcuts')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: requireAuthGuard,
  component: ShortcutsPage,
})
