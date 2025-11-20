import { createFileRoute } from '@tanstack/react-router'

import { requireAuthGuard } from '@/features/auth'

import ProfilePage from '@/widgets/profile/ProfilePage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(app)/profile')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: requireAuthGuard,
  component: ProfilePage,
})
