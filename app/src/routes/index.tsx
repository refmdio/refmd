import { createFileRoute, redirect } from '@tanstack/react-router'

// Remove placeholder landing page. Redirect '/' to the app dashboard.
export const Route = createFileRoute('/')({
  beforeLoad: () => {
    throw redirect({ to: '/dashboard' })
  },
  component: () => null,
})
