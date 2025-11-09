import { createFileRoute, useSearch } from '@tanstack/react-router'

import { SignInPage } from '@/widgets/auth/SignInPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(auth)/auth/signin')({
  staticData: { layout: 'auth' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SignInRoute,
})

type SignInSearch = {
  redirect?: string
  redirectSearch?: string
}

function SignInRoute() {
  const search = useSearch({ from: '/(auth)/auth/signin' }) as SignInSearch
  return <SignInPage redirect={search.redirect} redirectSearch={search.redirectSearch} />
}
