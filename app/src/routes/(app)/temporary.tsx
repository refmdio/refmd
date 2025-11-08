import { createFileRoute, Outlet, useNavigate, useRouterState } from '@tanstack/react-router'
import { useEffect } from 'react'

import { appBeforeLoadGuard } from '@/features/auth'
import { EditorOverlay } from '@/features/edit-document'
import { createTemporaryDocumentEntry } from '@/features/temporary-document'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(app)/temporary')({
  staticData: { layout: 'app' },
  beforeLoad: appBeforeLoadGuard,
  pendingComponent: () => <RoutePending label="Preparing temporary document…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: TemporaryRedirect,
})

function TemporaryRedirect() {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const normalizedPath = pathname.replace(/\/+$/, '') || '/'
  const isIndexPath = normalizedPath === '/temporary'

  useEffect(() => {
    if (!isIndexPath || typeof window === 'undefined') return
    try {
      const entry = createTemporaryDocumentEntry()
      navigate({ to: '/temporary/$id', params: { id: entry.id }, replace: true })
    } catch (error) {
      console.error('[temporary] failed to create scratchpad', error)
    }
  }, [isIndexPath, navigate])

  if (!isIndexPath) {
    return <Outlet />
  }

  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      <EditorOverlay label="Starting temporary note…" />
    </div>
  )
}
