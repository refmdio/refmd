import { createFileRoute } from '@tanstack/react-router'

import { authPageGuard } from '@/features/auth/lib/guards'

import { SignUpPage } from '@/widgets/auth/SignUpPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(auth)/auth/signup')({
  staticData: { layout: 'auth' },
  beforeLoad: authPageGuard,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SignUpPage,
})
