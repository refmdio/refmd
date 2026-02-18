import { createRouter } from '@tanstack/react-router'

// Import the generated route tree
import { routeTree } from './routeTree.gen'

// RouterContext is defined in a separate module to avoid circular dependencies
// between router.tsx and routeTree.gen.ts (TanStack Router codegen pattern).
export type { RouterContext } from '@/shared/router-context'

// Create a new router instance
export const getRouter = () => {
  const router = createRouter({
    routeTree,
    context: {},

    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
  })

  return router
}
