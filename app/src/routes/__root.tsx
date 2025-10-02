import { QueryClientProvider } from '@tanstack/react-query'
import { HeadContent, Scripts, Outlet, createRootRouteWithContext, useRouter, useRouterState } from '@tanstack/react-router'
import { type ReactNode } from 'react'

import '@/styles.css'

import { ShareTokenProvider } from '@/shared/contexts/share-token-context'
import { ThemeProvider } from '@/shared/contexts/theme-context'
import { getEnv } from '@/shared/lib/config'
import { Toaster } from '@/shared/ui/sonner'

import { AuthProvider } from '@/features/auth'
import { EditorProvider, ViewProvider } from '@/features/edit-document'
import { SecondaryViewerProvider } from '@/features/secondary-viewer'

import AppLayout from '@/widgets/layouts/AppLayout'
import AuthLayout from '@/widgets/layouts/AuthLayout'
import PublicLayout from '@/widgets/layouts/PublicLayout'
import PluginFallback from '@/widgets/routes/PluginFallback'

import { RealtimeProvider, useRealtime } from '@/processes/collaboration/contexts/realtime-context'

import type { RouterContext } from '@/router'

export const Route = createRootRouteWithContext<RouterContext>()({
  head: () => {
    const env = {
      VITE_API_BASE_URL: getEnv('VITE_API_BASE_URL'),
      VITE_PUBLIC_BASE_URL: getEnv('VITE_PUBLIC_BASE_URL'),
    }

    const themeBootstrapScript = `;(function(){try{var root=document.documentElement;var stored=localStorage.getItem('theme');var theme=stored==='dark'||stored==='light'?stored:null;if(!theme&&window.matchMedia){theme=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}if(!theme){theme='light';}root.classList.toggle('dark',theme==='dark');root.dataset.theme=theme;}catch(_){}})();`

    return {
      title: 'RefMD',
      meta: [
        { charSet: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1.0' },
        { name: 'description', content: 'RefMD - Real-time Collaborative Markdown Editor' },
        { name: 'robots', content: 'noindex, nofollow' },
        { name: 'theme-color', content: '#ffffff', media: '(prefers-color-scheme: light)' },
        { name: 'theme-color', content: '#0b0b0b', media: '(prefers-color-scheme: dark)' },
      ],
      links: [
        { rel: 'icon', href: '/favicon.ico' },
        { rel: 'apple-touch-icon', href: '/refmd-192.png' },
        { rel: 'manifest', href: '/manifest.json' },
      ],
      scripts: [
        {
          type: 'application/javascript',
          children: themeBootstrapScript,
        },
        {
          type: 'application/javascript',
          children: `window.__ENV__ = ${JSON.stringify(env)};`,
        },
      ],
    }
  },
  notFoundComponent: () => <PluginFallback />,
  component: RootComponent,
  shellComponent: RootDocument,
})

type LayoutKey = 'app' | 'document' | 'public' | 'share' | 'auth'

function RootComponent() {
  const router = useRouter()
  const queryClient = router.options.context.queryClient

  if (!queryClient) {
    throw new Error('QueryClient is not available in the router context')
  }

  const layout =
    useRouterState({
      select: (state) => {
        const matches = state.matches as Array<{ staticData?: { layout?: LayoutKey } }> | undefined
        const last = matches?.[matches.length - 1]
        return last?.staticData?.layout ?? 'app'
      },
    }) ?? 'app'

  const shareToken = useRouterState({
    select: (state) => {
      const matches = (state.matches as any[]) ?? []
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
}

function RootDocument({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  )
}

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
