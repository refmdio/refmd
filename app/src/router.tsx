import type { QueryClient } from '@tanstack/react-query'
import { createRouter } from '@tanstack/react-router'
import { setupRouterSsrQueryIntegration } from '@tanstack/react-router-ssr-query'

import { createQueryClient } from '@/shared/lib/queryClient'

import { routeTree } from './routeTree.gen'

export interface RouterContext {
  queryClient: QueryClient
}

export const getRouter = () => {
  const queryClient = createQueryClient()
  const context: RouterContext = { queryClient }

  const router = createRouter({
    routeTree,
    context,
    defaultPreload: 'intent',
    defaultPreloadStaleTime: 0,
    defaultStructuralSharing: true,
    scrollRestoration: true,
  })

  setupRouterSsrQueryIntegration({
    router,
    queryClient,
    wrapQueryClient: false,
  })

  return router
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>
    context: RouterContext
  }
}
