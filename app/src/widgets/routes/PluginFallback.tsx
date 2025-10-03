import { useNavigate } from '@tanstack/react-router'
import React from 'react'

import { useAuthContext } from '@/features/auth'
import {
  mountRoutePlugin,
  resolvePluginForRoute,
  type RoutePluginMatch,
} from '@/features/plugins'

import { useRealtime } from '@/processes/collaboration/contexts/realtime-context'

export default function PluginFallback() {
  const navigate = useNavigate()
  const { user, loading: authLoading } = useAuthContext()
  const realtime = useRealtime()
  const authReady = !authLoading && !!user
  const [manifestLoading, setManifestLoading] = React.useState(true)
  const [pluginMounting, setPluginMounting] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [plugin, setPlugin] = React.useState<RoutePluginMatch | null>(null)
  const containerRef = React.useRef<HTMLDivElement | null>(null)
  const disposeRef = React.useRef<null | (() => void)>(null)

  React.useEffect(() => {
    if (authLoading || authReady) return

    const location = (() => {
      try {
        if (typeof window === 'undefined') {
          return { pathname: '/', search: '' }
        }
        return { pathname: window.location.pathname, search: window.location.search }
      } catch {
        return { pathname: '/', search: '' }
      }
    })()

    const redirectSearch = location.search && location.search !== '?' ? location.search : ''

    navigate({
      to: '/auth/signin',
      search: redirectSearch
        ? { redirect: location.pathname, redirectSearch }
        : { redirect: location.pathname },
    })
  }, [authLoading, authReady, navigate])

  React.useEffect(() => {
    if (!authReady) return
    let cancelled = false

    const path = (() => {
      try {
        return window.location.pathname + window.location.search + window.location.hash
      } catch {
        return ''
      }
    })()

    setManifestLoading(true)
    setError(null)
    setPlugin(null)

    ;(async () => {
      try {
        const match = await resolvePluginForRoute(path)
        if (cancelled) return
        if (!match) {
          setError('Not Found')
        }
        setPlugin(match)
      } catch (e: any) {
        if (!cancelled) {
          console.error('[plugins] route plugin resolution failed', e)
          setError(e?.message || 'Failed to resolve plugin')
        }
      } finally {
        if (!cancelled) {
          setManifestLoading(false)
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [authReady])

  React.useEffect(() => {
    if (!authReady) return
    let cancelled = false
    const container = containerRef.current

    if (!container || !plugin) {
      if (disposeRef.current) {
        try {
          disposeRef.current()
        } catch {
          /* noop */
        }
        disposeRef.current = null
      }
      if (container) {
        try {
          container.innerHTML = ''
        } catch {
          /* noop */
        }
      }
      realtime.setDocumentTitle(undefined)
      realtime.setDocumentStatus(undefined)
      realtime.setDocumentBadge(undefined)
      realtime.setDocumentActions([])
      setPluginMounting(false)
      return
    }

    container.innerHTML = ''
    setPluginMounting(true)

    ;(async () => {
      try {
        const dispose = await mountRoutePlugin(
          plugin,
          container,
          {
            navigate: (to) => navigate({ to }),
            setDocumentTitle: realtime.setDocumentTitle,
            setDocumentStatus: realtime.setDocumentStatus,
            setDocumentBadge: realtime.setDocumentBadge,
            setDocumentActions: realtime.setDocumentActions,
          },
        )
        if (cancelled) {
          if (typeof dispose === 'function') {
            try {
              dispose()
            } catch {
              /* noop */
            }
          }
          return
        }
        disposeRef.current = dispose
      } catch (e: any) {
        if (!cancelled) {
          console.error('[plugins] route plugin mount failed', e)
          setError(e?.message || 'Failed to load plugin')
        }
      } finally {
        if (!cancelled) {
          setPluginMounting(false)
        }
      }
    })()

    return () => {
      cancelled = true
      if (disposeRef.current) {
        try {
          disposeRef.current()
        } catch {
          /* noop */
        }
        disposeRef.current = null
      }
      try {
        container.innerHTML = ''
      } catch {
        /* noop */
      }
      realtime.setDocumentTitle(undefined)
      realtime.setDocumentStatus(undefined)
      realtime.setDocumentBadge(undefined)
      realtime.setDocumentActions([])
    }
  }, [plugin, navigate, authReady])

  if (authLoading || !authReady) {
    return <div className="p-6 text-sm text-muted-foreground">Checking access…</div>
  }

  if (manifestLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading…</div>
  }

  if (error && !pluginMounting) {
    return <div className="p-6 text-sm text-muted-foreground">{error}</div>
  }

  return (
    <div className="relative h-full w-full">
      <div ref={containerRef} className="h-full w-full overflow-auto" />
      {(pluginMounting || manifestLoading) && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-background/80">
          <p className="text-sm text-muted-foreground">Preparing plugin…</p>
        </div>
      )}
    </div>
  )
}
