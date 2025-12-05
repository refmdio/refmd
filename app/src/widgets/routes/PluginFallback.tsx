import { useNavigate, useRouterState } from '@tanstack/react-router'
import React from 'react'

import { useRealtime } from '@/shared/contexts/realtime-context'
import { useShareToken } from '@/shared/contexts/share-token-context'

import { fetchDocumentMeta } from '@/entities/document'

import { useAuthContext } from '@/features/auth'
import {
  mountRoutePlugin,
  resolvePluginForRoute,
  type RoutePluginMatch,
} from '@/features/plugins'

import { SplitEditorPortalRenderer } from '@/widgets/plugins/SplitEditorHost'


export default function PluginFallback() {
  const navigate = useNavigate()
  const { user, loading: authLoading } = useAuthContext()
  const realtime = useRealtime()
  const shareTokenFromContext = useShareToken()
  const routerState = useRouterState()
  const search = routerState.location?.search ?? ''
  const authReady = !authLoading && !!user
  const shareToken = React.useMemo(() => {
    if (typeof shareTokenFromContext === 'string' && shareTokenFromContext.length > 0) {
      return shareTokenFromContext
    }
    try {
      if (typeof window !== 'undefined') {
        const params = new URLSearchParams(window.location.search)
        const value = params.get('token')
        if (value && value.trim().length > 0) return value
      }
      if (search && search.length > 0) {
        const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)
        const value = params.get('token')
        if (value && value.trim().length > 0) return value
      }
    } catch {
      /* noop */
    }
    return null
  }, [search, shareTokenFromContext])
  const allowAnonymous = Boolean(shareToken)
  const pluginAccessReady = allowAnonymous || authReady
  const [manifestLoading, setManifestLoading] = React.useState(true)
  const [pluginMounting, setPluginMounting] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [plugin, setPlugin] = React.useState<RoutePluginMatch | null>(null)
  const containerRef = React.useRef<HTMLDivElement | null>(null)
  const disposeRef = React.useRef<null | (() => void)>(null)

  React.useEffect(() => {
    if (allowAnonymous || authLoading || authReady) return

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
  }, [allowAnonymous, authLoading, authReady, navigate])

  React.useEffect(() => {
    if (!pluginAccessReady) return
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
    realtime.setDocumentId(undefined)

    ;(async () => {
      try {
        // If the path looks like a document route and has no plugin owner hint,
        // skip plugin resolution to avoid unnecessary work.
        const docIdMatch = path.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)
        if (docIdMatch) {
          try {
            const meta = await fetchDocumentMeta(docIdMatch[0], shareToken ?? undefined)
            const createdByPlugin = (meta as any)?.created_by_plugin ?? (meta as any)?.createdByPlugin
            if (!createdByPlugin) {
              if (!cancelled) {
                setError('Not Found')
                setManifestLoading(false)
              }
              return
            }
          } catch {
            /* ignore meta failures and continue to plugin resolution */
          }
        }

        const match = await resolvePluginForRoute(path, { token: shareToken ?? undefined })
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
  }, [pluginAccessReady, shareToken])

  React.useEffect(() => {
    if (!pluginAccessReady) return
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
      realtime.setDocumentId(undefined)
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
            setDocumentId: realtime.setDocumentId,
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
      realtime.setDocumentId(undefined)
      realtime.setDocumentTitle(undefined)
      realtime.setDocumentStatus(undefined)
      realtime.setDocumentBadge(undefined)
      realtime.setDocumentActions([])
    }
  }, [plugin, navigate, pluginAccessReady])

  if (!pluginAccessReady) {
    if (authLoading && !allowAnonymous) {
      return <div className="p-6 text-sm text-muted-foreground">Checking access…</div>
    }
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
      <SplitEditorPortalRenderer />
      <div ref={containerRef} className="h-full w-full overflow-auto" />
      {(pluginMounting || manifestLoading) && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-background/80">
          <p className="text-sm text-muted-foreground">Preparing plugin…</p>
        </div>
      )}
    </div>
  )
}
