import type { RouterContext } from '../router'

declare module '@tanstack/react-router' {
  interface Register {
    context: RouterContext
  }
}

declare module '@tanstack/router-core' {
  interface Register {
    context: RouterContext
  }
}
