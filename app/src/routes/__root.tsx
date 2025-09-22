// react import not required with react-jsx runtime
import { QueryClientProvider } from '@tanstack/react-query'
import { Outlet, createRootRoute, useRouterState } from '@tanstack/react-router'



import { ThemeProvider } from '@/shared/contexts/theme-context'
import { queryClient } from '@/shared/lib/queryClient'
import { Toaster } from '@/shared/ui/sonner'

import { AuthProvider } from '@/features/auth'
import { EditorProvider, ViewProvider } from '@/features/edit-document'
import { SecondaryViewerProvider } from '@/features/secondary-viewer'

import AppLayout from '@/widgets/layouts/AppLayout'
import AuthLayout from '@/widgets/layouts/AuthLayout'
import PublicLayout from '@/widgets/layouts/PublicLayout'
import PluginFallback from '@/widgets/routes/PluginFallback'

import { RealtimeProvider, useRealtime } from '@/processes/collaboration/contexts/realtime-context'
import { ShareTokenProvider } from '@/shared/contexts/share-token-context'

export const Route = createRootRoute({
  notFoundComponent: () => <PluginFallback />,
  component: () => {
    const layout =
      useRouterState({
        select: (s) => {
          const m = (s.matches as any)?.[(s.matches as any)?.length - 1]
          return (m?.staticData?.layout as 'app' | 'document' | 'public' | 'share' | 'auth' | undefined) ?? 'app'
        },
      }) ?? 'app'
    const shareToken = useRouterState({
      select: (s) => {
        const matches = (s.matches as any[]) ?? []
        for (let i = matches.length - 1; i >= 0; i--) {
          const match = matches[i]
          const fromLoader = match?.loaderData?.token
          if (typeof fromLoader === 'string' && fromLoader.length > 0) {
            return fromLoader
          }
          const fromSearch = match?.search?.token
          if (typeof fromSearch === 'string' && fromSearch.length > 0) {
            return fromSearch
          }
        }
        return undefined
      },
    })
    return (
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>
            <RealtimeProvider>
              <SecondaryViewerProvider>
                <ShareTokenProvider token={shareToken}>
                  <LayoutContent layout={layout} />
                </ShareTokenProvider>
                <Toaster richColors position="bottom-right" />
              </SecondaryViewerProvider>
            </RealtimeProvider>
          </AuthProvider>
        </QueryClientProvider>
      </ThemeProvider>
    )
  },
})

type LayoutKey = 'app' | 'document' | 'public' | 'share' | 'auth'

function LayoutContent({ layout }: { layout: LayoutKey }) {
  const realtime = useRealtime()

  if (layout === 'auth') {
    return (
      <AuthLayout>
        <Outlet />
      </AuthLayout>
    )
  }

  if (layout === 'public') {
    return (
      <PublicLayout>
        <Outlet />
      </PublicLayout>
    )
  }

  if (layout === 'share') {
    return (
      <EditorProvider>
        <ViewProvider>
          <AppLayout realtime={realtime}>
            <Outlet />
          </AppLayout>
        </ViewProvider>
      </EditorProvider>
    )
  }

  return (
    <EditorProvider>
      <ViewProvider>
        <AppLayout realtime={realtime}>
          <Outlet />
        </AppLayout>
      </ViewProvider>
    </EditorProvider>
  )
}
