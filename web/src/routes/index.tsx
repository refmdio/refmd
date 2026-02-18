import { createFileRoute, redirect } from '@tanstack/react-router'
import { hasResumableSession } from '@/features/auth'

export const Route = createFileRoute('/')({
  beforeLoad: async () => {
    if (await hasResumableSession()) {
      throw redirect({ to: '/dashboard' })
    } else {
      throw redirect({ to: '/auth/login' })
    }
  },
})
