import { useEffect, useState } from 'react'


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
  const [status, setStatus] = useState<'idle' | 'checking' | 'redirecting'>('idle')

  useEffect(() => {
    if (!enabled || !docId) {
      setStatus('idle')
      return
    }
    if (typeof window === 'undefined') {
      setStatus('idle')
      return
    }

    let cancelled = false
    setStatus('checking')

    const normalizeRoute = (value: string | null | undefined) => {
      if (!value) return null
      try {
        const url = new URL(value, window.location.origin)
        return url.pathname + url.search + url.hash
      } catch {
        return value
      }
    }

    const navigateTo = async (target: string) => {
      if (!target) return false
      if (externalNavigate) {
        try {
          await Promise.resolve(externalNavigate(target))
          return true
        } catch {
          /* fall back */
        }
      }
      const nav = (window as any).router?.navigate
      if (typeof nav === 'function') {
        try {
          await Promise.resolve(nav({ to: target }))
          return true
        } catch {
          /* fall back */
        }
      }
      try {
        window.location.href = target
        return true
      } catch {
        return false
      }
    }

    const run = async () => {
      try {
        const searchParams = new URLSearchParams(window.location.search)
        const shareToken = (() => {
          const value = searchParams.get('token')
          return value && value.trim().length > 0 ? value : undefined
        })()
        const manifest = await getPluginManifest(shareToken)
        if (!Array.isArray(manifest) || manifest.length === 0) {
          if (!cancelled) setStatus('idle')
          return
        }
        const currentRoute = window.location.pathname + window.location.search + window.location.hash
        const currentNormalized = normalizeRoute(currentRoute)

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
          if (!cancelled) setStatus('idle')
          return
        }

        const modules = await Promise.allSettled(candidates.map((c) => c.loader))

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
            if (!cancelled) setStatus('redirecting')
            const to = await mod.getRoute(docId, { token: shareToken, origin, host })
            if (typeof to === 'string' && to) {
              const normalizedTarget = normalizeRoute(to)
              const isSameRoute = normalizedTarget && currentNormalized && normalizedTarget === currentNormalized
              if (isSameRoute) {
                if (!cancelled) setStatus('idle')
                continue
              }
              const navigated = await navigateTo(to)
              if (!navigated && !cancelled) {
                setStatus('idle')
              }
              return
            }
          } catch (error) {
            console.error('[plugins] redirect resolution failed', candidate?.plugin?.id ?? 'unknown', error)
          }
        }
        if (!cancelled) setStatus('idle')
      } catch (error) {
        console.error('[plugins] redirect orchestration failed', error)
        if (!cancelled) setStatus('idle')
      }
    }

    void run()
    return () => {
      cancelled = true
    }
  }, [docId, enabled, externalNavigate])

  return {
    redirecting: status === 'redirecting',
    resolving: status !== 'idle',
  }
}
