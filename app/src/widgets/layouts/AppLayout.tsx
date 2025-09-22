import React from 'react'
import type { ImperativePanelHandle } from 'react-resizable-panels'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/shared/ui/resizable'
import { SidebarProvider, Sidebar, SidebarInset } from '@/shared/ui/sidebar'

import { Header, type HeaderRealtimeState } from '@/widgets/header/Header'
import DevtoolsPortal from '@/widgets/layouts/DevtoolsPortal'
import AppSidebar from '@/widgets/sidebar/AppSidebar'

type Props = {
  children: React.ReactNode
  realtime?: HeaderRealtimeState
}

export default function AppLayout({ children, realtime }: Props) {
  const isMobile = useIsMobile()
  const [sidebarOpen, setSidebarOpen] = React.useState(true)
  const sidebarPanelRef = React.useRef<ImperativePanelHandle | null>(null)
  const DESKTOP_SIDEBAR_DEFAULT = 20

  React.useEffect(() => {
    if (isMobile) return
    const p = sidebarPanelRef.current
    if (!p) return
    try {
      if (sidebarOpen) {
        p.expand?.()
        p.resize?.(DESKTOP_SIDEBAR_DEFAULT)
      } else {
        p.collapse?.()
      }
    } catch {}
  }, [sidebarOpen, isMobile, DESKTOP_SIDEBAR_DEFAULT])

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
