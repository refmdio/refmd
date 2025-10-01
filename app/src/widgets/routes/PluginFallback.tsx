import { useNavigate } from '@tanstack/react-router'
import React from 'react'

import { resolveAuthRedirect } from '@/features/auth'
import {
  mountRoutePlugin,
  resolvePluginForRoute,
  type RoutePluginMatch,
} from '@/features/plugins'

export default function PluginFallback() {
  const navigate = useNavigate()
  const [authChecking, setAuthChecking] = React.useState(true)
  const [authReady, setAuthReady] = React.useState(false)
  const [manifestLoading, setManifestLoading] = React.useState(true)
  const [pluginMounting, setPluginMounting] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [plugin, setPlugin] = React.useState<RoutePluginMatch | null>(null)
  const containerRef = React.useRef<HTMLDivElement | null>(null)
  const disposeRef = React.useRef<null | (() => void)>(null)

  React.useEffect(() => {
    let cancelled = false

    const run = async () => {
      setAuthChecking(true)
      setAuthReady(false)
      try {
        const locationCtx = typeof window !== 'undefined'
          ? { location: { pathname: window.location.pathname, search: window.location.search } }
          : undefined
        const redirectTarget = await resolveAuthRedirect(locationCtx)
        if (cancelled) return
        if (redirectTarget) {
          navigate(redirectTarget)
          return
        }
        setAuthReady(true)
      } catch (e) {
        if (!cancelled) {
          console.error('[plugins] route auth precheck failed', e)
          setAuthReady(true)
        }
      } finally {
        if (!cancelled) {
          setAuthChecking(false)
        }
      }
    }

    run()

    return () => {
      cancelled = true
    }
  }, [navigate])

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
      setPluginMounting(false)
      return
    }

    container.innerHTML = ''
    setPluginMounting(true)

    ;(async () => {
      try {
        const dispose = await mountRoutePlugin(plugin, container, (to) => navigate({ to }))
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
    }
  }, [plugin, navigate, authReady])

  if (authChecking) {
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
