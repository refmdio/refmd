import { createFileRoute, useSearch } from '@tanstack/react-router'

import { authPageGuard } from '@/features/auth/lib/guards'

import { SignInPage } from '@/widgets/auth/SignInPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(auth)/auth/signin')({
  staticData: { layout: 'auth' },
  beforeLoad: authPageGuard,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: SignInRoute,
})

type SignInSearch = {
  redirect?: string
  redirectSearch?: string
  provider?: string
  code?: string
  state?: string
  error?: string
}

function SignInRoute() {
  const search = useSearch({ from: '/(auth)/auth/signin' }) as SignInSearch
  return (
    <SignInPage
      redirect={search.redirect}
      redirectSearch={search.redirectSearch}
      oauthProvider={search.provider}
      oauthCode={search.code}
      oauthState={search.state}
      oauthError={search.error}
    />
  )
}
