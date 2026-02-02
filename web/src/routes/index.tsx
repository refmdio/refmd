import { useEffect } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { authApi, ApiRequestError } from '@/shared/api'

export const Route = createFileRoute('/')({
  component: IndexPage,
})

function IndexPage() {
  const navigate = useNavigate()

  useEffect(() => {
    async function checkAuth() {
      try {
        await authApi.me()
        // Authenticated - redirect to dashboard
        navigate({ to: '/dashboard', replace: true })
      } catch (error) {
        if (error instanceof ApiRequestError && error.status === 401) {
          // Not authenticated - redirect to login
          navigate({ to: '/auth/login', replace: true })
        }
      }
    }

    checkAuth()
  }, [navigate])

  // Show nothing while checking auth
  return null
}
