import { useQuery } from '@tanstack/react-query'
import { createFileRoute, useSearch } from '@tanstack/react-router'

import { authProvidersQuery } from '@/entities/user'

import { authPageGuard } from '@/features/auth/lib/guards'


import { SignInPage } from '@/widgets/auth/SignInPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(auth)/auth/signin')({
  staticData: { layout: 'auth' },
  beforeLoad: authPageGuard,
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: ({ context }) => {
    context.queryClient
      .prefetchQuery(authProvidersQuery())
      .catch((error) => {
        console.warn('[signin] failed to prefetch auth providers', error)
      })
    return null
  },
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
  const { data, isLoading, isFetching, isError, refetch } = useQuery(authProvidersQuery())
  return (
    <SignInPage
      redirect={search.redirect}
      redirectSearch={search.redirectSearch}
      oauthProvider={search.provider}
      oauthCode={search.code}
      oauthState={search.state}
      oauthError={search.error}
      providers={data?.providers}
      providerLoadFailed={isError}
      providersLoading={isLoading || isFetching}
      onRetryProviders={() => refetch()}
    />
  )
}
