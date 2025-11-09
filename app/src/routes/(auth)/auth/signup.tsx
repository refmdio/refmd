import { createFileRoute } from '@tanstack/react-router'

import { SignUpPage } from '@/widgets/auth/SignUpPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(auth)/auth/signup')({
  staticData: { layout: 'auth' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SignUpPage,
})
