import { createFileRoute, redirect } from '@tanstack/react-router'
import { WORKSPACE_STORAGE_KEY } from '@/entities/workspace'

export const Route = createFileRoute('/')({
  beforeLoad: async () => {
    const persisted = typeof window !== 'undefined' ? localStorage.getItem(WORKSPACE_STORAGE_KEY) : null
    if (persisted) {
      throw redirect({ to: '/workspace/$workspaceId', params: { workspaceId: persisted } })
    }

    // No persisted workspace. Redirect to the workspace resolver inside
    // the _authenticated layout. If the user is not authenticated, the
    // layout's guard will redirect them to /auth/login. This avoids
    // sending session-restorable users to /auth/login unnecessarily.
    throw redirect({ to: '/workspace' })
  },
})
