import { createRouter } from '@tanstack/react-router'

// Import the generated route tree
import { routeTree } from './routeTree.gen'

export interface RouterContext {
  auth: {
    isAuthenticated: boolean
  }
}

// Create a new router instance
export const getRouter = () => {
  const router = createRouter({
    routeTree,
    context: {
      auth: {
        isAuthenticated: false,
      },
    },

    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
  })

  return router
}
