import { useEffect, useState } from 'react'
import { useRef } from 'react'


import type { PluginManifestItem } from '@/entities/plugin'
import { getPluginManifest } from '@/entities/plugin'

import {
  createPluginHost,
  loadPluginModule,
} from '@/features/plugins/lib/runtime'


type Options = {
  enabled?: boolean
  navigate?: (to: string) => void | Promise<void>
}

export function usePluginDocumentRedirect(docId: string, options: Options = {}) {
  const { enabled = true, navigate: externalNavigate } = options
  const [redirecting, setRedirecting] = useState(false)
  const navigateRef = useRef<typeof externalNavigate>(externalNavigate)

  useEffect(() => {
    navigateRef.current = externalNavigate
  }, [externalNavigate])

  useEffect(() => {
    if (!enabled || !docId) {
      setRedirecting(false)
      return
    }
    if (typeof window === 'undefined') {
      setRedirecting(false)
      return
    }

    let cancelled = false
    // Block edits while we decide if a plugin wants to take over this document.
    setRedirecting(true)
    // Failsafe: never leave the overlay stuck if something inside `run` hangs.
    const timeoutId = window.setTimeout(() => {
      if (!cancelled) setRedirecting(false)
    }, 5000)

    const run = async () => {
      try {
        const searchParams = new URLSearchParams(window.location.search)
        const shareToken = (() => {
          const value = searchParams.get('token')
          return value && value.trim().length > 0 ? value : undefined
        })()
        const manifest = await getPluginManifest(shareToken)
        if (!Array.isArray(manifest) || manifest.length === 0) {
          return
        }
        const currentRoute = window.location.pathname + window.location.search + window.location.hash

        const candidates = (manifest as PluginManifestItem[])
          .map((plugin) => {
            const entry = (plugin as any)?.frontend?.entry?.trim?.()
            if (!entry) return null
            const mode = (plugin as any)?.frontend?.mode
            if (mode && String(mode).toLowerCase() !== 'esm') return null
            return {
              plugin,
              loader: loadPluginModule(plugin as any),
            }
          })
          .filter((value): value is { plugin: PluginManifestItem; loader: Promise<any> } => value !== null)

        if (candidates.length === 0) {
          return
        }

        const modules = await Promise.allSettled(candidates.map((c) => c.loader))

        const navigateTo = (target: string) => {
          if (!target) return
          const externalNavigate = navigateRef.current
          if (externalNavigate) {
            try {
              const result = externalNavigate(target)
              if (result && typeof (result as Promise<void>).catch === 'function') {
                ;(result as Promise<void>).catch(() => {
                  window.location.href = target
                })
              }
              return
            } catch {
              window.location.href = target
              return
            }
          }
          const nav = (window as any).router?.navigate
          if (typeof nav === 'function') {
            try {
              nav({ to: target })
              return
            } catch {}
          }
          window.location.href = target
        }

        for (let index = 0; index < candidates.length; index += 1) {
          const candidate = candidates[index]
          const moduleResult = modules[index]
          if (moduleResult.status !== 'fulfilled') {
            console.error('[plugins] redirect module load failed', candidate?.plugin?.id, moduleResult.reason)
            continue
          }

          const mod = moduleResult.value
          if (!mod || typeof mod.canOpen !== 'function') continue

          try {
            const host = await createPluginHost(candidate.plugin as any, {
              mode: 'primary',
              docId,
              token: shareToken,
              route: currentRoute,
              navigate: navigateTo,
            })
            const origin = (host as any)?.origin || ''
            const canOpen = await mod.canOpen(docId, { token: shareToken, origin, host })
            if (!canOpen || typeof mod.getRoute !== 'function') continue
            if (!cancelled) setRedirecting(true)
            const to = await mod.getRoute(docId, { token: shareToken, origin, host })
            if (typeof to === 'string' && to) {
              navigateTo(to)
              return
            }
          } catch (error) {
            console.error('[plugins] redirect resolution failed', candidate?.plugin?.id ?? 'unknown', error)
          }
        }
      } catch (error) {
        console.error('[plugins] redirect orchestration failed', error)
      } finally {
        clearTimeout(timeoutId)
        if (!cancelled) setRedirecting(false)
      }
    }

    void run()
    return () => {
      cancelled = true
      clearTimeout(timeoutId)
    }
  }, [docId, enabled])

  return redirecting
}
