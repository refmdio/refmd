import type { PluginManifestItem } from '@/entities/plugin'
import { getPluginManifest, getPluginKv } from '@/entities/plugin'

import {
  createPluginHost,
  getApiOrigin,
  loadPluginModule,
} from '@/features/plugins/lib/runtime'

export type RoutePluginMatch = {
  manifest: PluginManifestItem
  module: any
}

export type DocumentPluginMatch = {
  manifest: PluginManifestItem
  module: any
  route: string
  token: string | null
  docId: string
}

export async function resolvePluginForRoute(path: string): Promise<RoutePluginMatch | null> {
  const manifest = await getPluginManifest()

  const candidates = manifest
    .map((item) => {
      const mounts = Array.isArray(item.mounts) ? item.mounts : []
      const matched = mounts.some((mount) => matchesMount(mount, path))
      if (!matched) return null

      const frontend = item?.frontend as { entry?: string; mode?: string } | undefined
      const entry = frontend?.entry?.trim()
      if (!entry) return null
      if ((frontend?.mode || 'esm').toLowerCase() !== 'esm') return null

      return {
        item,
        loader: loadPluginModule(item),
      }
    })
    .filter((value): value is { item: PluginManifestItem; loader: Promise<any> } => value !== null)

  if (candidates.length === 0) return null

  const results = await Promise.allSettled(candidates.map((c) => c.loader))
  for (let index = 0; index < candidates.length; index += 1) {
    const result = results[index]
    if (result.status !== 'fulfilled') {
      console.error('[plugins] failed to load route plugin', candidates[index]?.item?.id, result.reason)
      continue
    }
    const mod = result.value
    if (!mod) continue
    return { manifest: candidates[index].item, module: mod }
  }

  return null
}

export async function resolvePluginForDocument(
  docId: string,
  token?: string | null,
  options: { source?: 'primary' | 'secondary' } = {},
): Promise<DocumentPluginMatch | null> {
  const manifest = await getPluginManifest()
  const apiOrigin = getApiOrigin()
  const detectionHost = {
    origin: apiOrigin,
    api: {
      getKv: (pluginId: string, docId2: string, key: string, tok?: string) =>
        getPluginKv(pluginId, docId2, key, tok),
    },
  }

  const candidates = manifest
    .map((item) => {
      const frontend = item?.frontend as { entry?: string; mode?: string } | undefined
      const entry = frontend?.entry?.trim()
      if (!entry) return null
      if ((frontend?.mode || 'esm').toLowerCase() !== 'esm') return null
      return {
        item,
        loader: loadPluginModule(item),
      }
    })
    .filter((value): value is { item: PluginManifestItem; loader: Promise<any> } => value !== null)

  if (candidates.length === 0) return null

  const results = await Promise.allSettled(candidates.map((c) => c.loader))

  for (let index = 0; index < candidates.length; index += 1) {
    const item = candidates[index].item
    const result = results[index]
    if (result.status !== 'fulfilled') {
      console.error('[plugins] failed to load document plugin', item?.id, result.reason)
      continue
    }

    const mod = result.value
    if (!mod) continue

    let route = `/document/${docId}`
    if (typeof mod.getRoute === 'function') {
      try {
        const res = await mod.getRoute(docId, {
          token,
          origin: apiOrigin,
          host: detectionHost,
          source: options.source ?? 'primary',
        })
        if (typeof res === 'string' && res) route = res
      } catch {
        /* noop */
      }
    }

    let canOpen = true
    if (typeof mod.canOpen === 'function') {
      try {
        canOpen = await mod.canOpen(docId, {
          token,
          origin: apiOrigin,
          host: detectionHost,
          source: options.source ?? 'primary',
        })
      } catch {
        canOpen = false
      }
    }

    const mounts = Array.isArray(item.mounts) ? item.mounts : []
    const currentPath = getCurrentPathname()
    const locationMatches = currentPath ? mounts.some((mount) => matchesMount(mount, currentPath)) : false

    if (!canOpen && !locationMatches) continue

    let routeToken: string | null = null
    try {
      const url = new URL(route, window.location.origin)
      routeToken = url.searchParams.get('token')
    } catch {
      /* noop */
    }

    return {
      manifest: item,
      module: mod,
      route,
      token: routeToken ?? token ?? null,
      docId,
    }
  }

  return null
}

export function matchesMount(mount: string, path: string) {
  if (!mount || !path) return false
  const cleanPath = path.split('?')[0] || path

  if (mount.startsWith('^')) {
    try {
      const regex = new RegExp(mount)
      return regex.test(cleanPath)
    } catch {
      /* noop */
    }
  }

  if (mount.includes('*')) {
    const escaped = mount
      .split('*')
      .map((segment) => segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*')
    try {
      const regex = new RegExp(`^${escaped}$`)
      return regex.test(cleanPath)
    } catch {
      return false
    }
  }

  if (mount.endsWith('/*')) {
    const base = mount.slice(0, -2)
    if (cleanPath === base) return true
    const prefix = base.endsWith('/') ? base : `${base}/`
    return cleanPath.startsWith(prefix)
  }

  return cleanPath === mount
}

function getCurrentPathname() {
  if (typeof window === 'undefined') return null
  try {
    return window.location.pathname
  } catch {
    return null
  }
}

export async function mountResolvedPlugin(
  match: DocumentPluginMatch,
  container: HTMLElement,
  mode: 'primary' | 'secondary',
) {
  const host = await createPluginHost(match.manifest, {
    docId: match.docId,
    route: match.route,
    token: match.token ?? undefined,
    mode,
  })

  try {
    ;(match.module as any).__host__ = host
  } catch {
    /* noop */
  }

  const dispose = await Promise.resolve(match.module?.default?.(container, host))
  return typeof dispose === 'function' ? dispose : null
}

export async function mountRoutePlugin(
  match: RoutePluginMatch,
  container: HTMLElement,
  navigate?: (to: string) => void | Promise<void>,
) {
  const host = await createPluginHost(match.manifest, {
    mode: 'primary',
    navigate,
  })
  try {
    ;(match.module as any).__host__ = host
  } catch {
    /* noop */
  }

  const dispose = await Promise.resolve(match.module?.default?.(container, host))
  return typeof dispose === 'function' ? dispose : null
}
