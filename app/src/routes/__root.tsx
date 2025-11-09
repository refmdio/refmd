import { QueryClientProvider } from '@tanstack/react-query'
import { HeadContent, Scripts, Outlet, createRootRouteWithContext, useRouter, useRouterState } from '@tanstack/react-router'
import { type ReactNode, useEffect, useRef, useState } from 'react'
import type { ImperativePanelHandle } from 'react-resizable-panels'

import '@/styles.css'

import { RealtimeProvider, useRealtime } from '@/shared/contexts/realtime-context'
import { ShareTokenProvider } from '@/shared/contexts/share-token-context'
import { ThemeProvider } from '@/shared/contexts/theme-context'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { useServiceWorker } from '@/shared/hooks/use-service-worker'
import { getEnv } from '@/shared/lib/config'
import type { HeaderRealtimeState } from '@/shared/types/header'
import DevtoolsPortal from '@/shared/ui/devtools/DevtoolsPortal'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/shared/ui/resizable'
import { SidebarProvider, Sidebar, SidebarInset } from '@/shared/ui/sidebar'
import { Toaster } from '@/shared/ui/sonner'

import { AuthProvider, useAuthContext } from '@/features/auth'
import { EditorProvider, ViewProvider } from '@/features/edit-document'
import { SecondaryViewerProvider } from '@/features/secondary-viewer'
import { ShortcutRegistryProvider } from '@/features/shortcuts'

import { Header } from '@/widgets/header/Header'
import AuthLayout from '@/widgets/layouts/AuthLayout'
import PublicLayout from '@/widgets/layouts/PublicLayout'
import PluginFallback from '@/widgets/routes/PluginFallback'
import AppSidebar from '@/widgets/sidebar/AppSidebar'


import type { RouterContext } from '@/router'

export const Route = createRootRouteWithContext<RouterContext>()({
  head: () => {
    const env = {
      VITE_API_BASE_URL: getEnv('VITE_API_BASE_URL'),
      VITE_PUBLIC_BASE_URL: getEnv('VITE_PUBLIC_BASE_URL'),
    }

    const serializedEnv = JSON.stringify(env)
      .replace(/</g, '\\u003c')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029')

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
        { rel: 'manifest', href: '/manifest.webmanifest' },
      ],
      scripts: [
        {
          type: 'application/javascript',
          children: themeBootstrapScript,
        },
        {
          type: 'application/javascript',
          children: `window.__ENV__ = ${serializedEnv};`,
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

  useServiceWorker()

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
          <ShortcutRegistryBoundary>
            <RealtimeProvider>
              <SecondaryViewerProvider>
                <ShareTokenProvider token={shareToken}>
                  <LayoutContent layout={layout} />
                </ShareTokenProvider>
                <Toaster richColors position="bottom-right" />
              </SecondaryViewerProvider>
            </RealtimeProvider>
          </ShortcutRegistryBoundary>
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

function ShortcutRegistryBoundary({ children }: { children: ReactNode }) {
  const { user } = useAuthContext()
  return <ShortcutRegistryProvider currentUserId={user?.id}>{children}</ShortcutRegistryProvider>
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
          <AppShellLayout realtime={realtime}>
            <Outlet />
          </AppShellLayout>
        </ViewProvider>
      </EditorProvider>
    )
  }

  return (
    <EditorProvider>
      <ViewProvider>
        <AppShellLayout realtime={realtime}>
          <Outlet />
        </AppShellLayout>
      </ViewProvider>
    </EditorProvider>
  )
}

function AppShellLayout({ realtime, children }: { realtime?: HeaderRealtimeState; children: ReactNode }) {
  const isMobile = useIsMobile()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const sidebarPanelRef = useRef<ImperativePanelHandle | null>(null)
  const DESKTOP_SIDEBAR_DEFAULT = 20

  useEffect(() => {
    if (isMobile) return
    const panel = sidebarPanelRef.current
    if (!panel) return
    try {
      if (sidebarOpen) {
        panel.expand?.()
        panel.resize?.(DESKTOP_SIDEBAR_DEFAULT)
      } else {
        panel.collapse?.()
      }
    } catch {}
  }, [isMobile, sidebarOpen, DESKTOP_SIDEBAR_DEFAULT])

  return (
    <SidebarProvider
      open={sidebarOpen}
      onOpenChange={setSidebarOpen}
      className={isMobile ? 'flex-col' : undefined}
    >
      {isMobile ? (
        <>
          <Header variant="mobile" realtime={realtime} />
          <Sidebar className="top-12">
            <AppSidebar />
          </Sidebar>
          <SidebarInset className="pt-12">
            {children}
            <DevtoolsPortal />
          </SidebarInset>
        </>
      ) : (
        <div className="relative flex h-svh w-full overflow-hidden bg-background">
          <ResizablePanelGroup
            direction="horizontal"
            className="flex-1"
            onLayout={(sizes) => {
              const first = Array.isArray(sizes) ? sizes[0] : undefined
              if (typeof first === 'number') {
                if (first < 5 && sidebarOpen) setSidebarOpen(false)
                if (first >= 5 && !sidebarOpen) setSidebarOpen(true)
              }
            }}
          >
            <ResizablePanel
              ref={sidebarPanelRef as any}
              defaultSize={DESKTOP_SIDEBAR_DEFAULT}
              minSize={sidebarOpen ? 8 : 0}
              maxSize={sidebarOpen ? 40 : 0}
              collapsible
              onCollapse={() => setSidebarOpen(false)}
              onExpand={() => setSidebarOpen(true)}
              className="overflow-visible bg-transparent"
            >
              <div className="h-full w-full overflow-hidden pl-5 sm:pl-6 lg:pl-8">
                <AppSidebar />
              </div>
            </ResizablePanel>
            <ResizableHandle className="!w-[0.375rem] !bg-transparent after:hidden cursor-col-resize" />
            <ResizablePanel defaultSize={100 - DESKTOP_SIDEBAR_DEFAULT} className="overflow-hidden">
              <div className="relative h-full w-full overflow-hidden px-5 sm:px-6 lg:px-8 pb-6 pt-[5.25rem] md:pt-[5.75rem] lg:pt-[6rem]">
                <Header variant="overlay" realtime={realtime} />
                <div className="relative z-10 flex h-full flex-col overflow-hidden">
                  {children}
                  <DevtoolsPortal />
                </div>
              </div>
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>
      )}
    </SidebarProvider>
  )
}
