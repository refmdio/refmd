import type { DocumentHeaderAction } from '@/shared/types/document'

import type { PluginManifestItem } from '@/entities/plugin'
import { getPluginManifest, getPluginKv } from '@/entities/plugin'

import {
  createPluginHost,
  applyShareTokenToRoute,
  getApiOrigin,
  loadPluginModule,
} from './runtime'

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

const PLUGIN_MANIFEST_CACHE_TTL_MS = 5_000
const pluginManifestCache = new Map<
  string,
  { ts: number; value?: PluginManifestItem[]; promise?: Promise<PluginManifestItem[]> }
>()

function buildPluginManifestCacheKey(args: { token?: string | null; workspaceId?: string | null }) {
  const token = args.token ?? ''
  const workspaceId = args.workspaceId ?? ''
  return `${workspaceId}:${token}`
}

async function getPluginManifestCached(args: { token?: string | null; workspaceId?: string | null }): Promise<PluginManifestItem[]> {
  const key = buildPluginManifestCacheKey(args)
  const now = Date.now()
  const cached = pluginManifestCache.get(key)
  if (cached) {
    if (cached.value && now - cached.ts < PLUGIN_MANIFEST_CACHE_TTL_MS) {
      return cached.value
    }
    if (cached.promise) {
      return cached.promise
    }
  }

  const promise = getPluginManifest(args.token ?? undefined)
    .then((value) => {
      pluginManifestCache.set(key, { ts: Date.now(), value })
      return value
    })
    .catch((error) => {
      const current = pluginManifestCache.get(key)
      if (current?.promise === promise) {
        pluginManifestCache.delete(key)
      }
      throw error
    })

  pluginManifestCache.set(key, { ts: now, promise })
  return promise
}

export async function resolvePluginForRoute(
  path: string,
  options: { token?: string | null; workspaceId?: string | null } = {},
): Promise<RoutePluginMatch | null> {
  const token = options.token ?? extractTokenFromPath(path)
  const manifest = await getPluginManifestCached({ token: token ?? undefined, workspaceId: options.workspaceId ?? null })

  for (const item of manifest) {
    const mounts = Array.isArray(item.mounts) ? item.mounts : []
    const matched = mounts.some((mount) => matchesMount(mount, path))
    if (!matched) continue

    const frontend = item?.frontend as { entry?: string; mode?: string } | undefined
    const entry = frontend?.entry?.trim()
    if (!entry) continue
    if ((frontend?.mode || 'esm').toLowerCase() !== 'esm') continue

    try {
      const mod = await loadPluginModule(item)
      if (!mod) continue
      return { manifest: item, module: mod }
    } catch (error) {
      console.error('[plugins] failed to load route plugin', item?.id, error)
    }
  }

  return null
}

export async function resolvePluginForDocumentById(
  docId: string,
  pluginId: string,
  token?: string | null,
  options: { source?: 'primary' | 'secondary'; document?: { type?: string | null }; workspaceId?: string | null } = {},
): Promise<DocumentPluginMatch | null> {
  const trimmedPluginId = pluginId?.trim?.() ?? ''
  if (!trimmedPluginId) return null
  const manifest = await getPluginManifestCached({ token: token ?? undefined, workspaceId: options.workspaceId ?? null })
  const apiOrigin = getApiOrigin()

  const item = (manifest as PluginManifestItem[]).find((entry) => String(entry?.id) === trimmedPluginId)
  if (!item) return null

  const frontend = item?.frontend as { entry?: string; mode?: string } | undefined
  const entry = frontend?.entry?.trim()
  if (!entry) return null
  if ((frontend?.mode || 'esm').toLowerCase() !== 'esm') return null

  let mod: any
  try {
    mod = await loadPluginModule(item as any)
  } catch (error) {
    console.error('[plugins] failed to load document plugin', item?.id, error)
    return null
  }
  if (!mod) return null

  const detectionHost = {
    origin: apiOrigin,
    exec: async (action: string, payload: any) => {
      const ok = (data: any) => ({ ok: true, data, effects: [], error: null })
      const fail = (code: string, message?: string) => ({
        ok: false,
        data: null,
        effects: [],
        error: { code, message },
      })
      try {
        switch (action) {
          case 'host.kv.get': {
            const lookupDocId = payload?.docId ?? docId
            const key = payload?.key
            const tok = payload?.token ?? token ?? undefined
            if (!lookupDocId || typeof key !== 'string' || !key) {
              return fail('BAD_REQUEST', 'docId and key required')
            }
            const data = await getPluginKv(item.id, lookupDocId, key, tok)
            return ok(data)
          }
          default:
            return fail('UNSUPPORTED_ACTION', `Unsupported host action: ${action}`)
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        return fail('HOST_ACTION_FAILED', message)
      }
    },
    api: {
      getKv: (pluginId2: string, docId2: string, key: string, tok?: string) =>
        getPluginKv(pluginId2, docId2, key, tok),
    },
  }

  let canOpen = true
  if (typeof mod.canOpen === 'function') {
    try {
      const docType = options.document?.type ?? null
      canOpen = await mod.canOpen(docId, {
        token,
        origin: apiOrigin,
        host: detectionHost,
        source: options.source ?? 'primary',
        document: options.document,
        docType: docType ?? undefined,
      })
    } catch {
      canOpen = false
    }
  }
  if (!canOpen) return null

  // Embed into the standard document route (tiles), not plugin-specific routes.
  const routeWithToken = applyShareTokenToRoute(`/document/${docId}`, token)

  let routeToken: string | null = routeWithToken.token
  try {
    const url = new URL(routeWithToken.route, window.location.origin)
    routeToken = routeToken ?? url.searchParams.get('token')
  } catch {
    /* noop */
  }

  return {
    manifest: item,
    module: mod,
    route: routeWithToken.route,
    token: routeToken ?? token ?? null,
    docId,
  }
}

export async function resolvePluginForDocument(
  docId: string,
  token?: string | null,
  options: { source?: 'primary' | 'secondary'; document?: { type?: string | null }; workspaceId?: string | null } = {},
): Promise<DocumentPluginMatch | null> {
  const manifest = await getPluginManifestCached({ token: token ?? undefined, workspaceId: options.workspaceId ?? null })
  const apiOrigin = getApiOrigin()

  for (const item of manifest) {
    const frontend = item?.frontend as { entry?: string; mode?: string } | undefined
    const entry = frontend?.entry?.trim()
    if (!entry) continue
    if ((frontend?.mode || 'esm').toLowerCase() !== 'esm') continue

    let mod: any
    try {
      mod = await loadPluginModule(item)
    } catch (error) {
      console.error('[plugins] failed to load document plugin', item?.id, error)
      continue
    }
    if (!mod) continue

    const detectionHost = {
      origin: apiOrigin,
      exec: async (action: string, payload: any) => {
        const ok = (data: any) => ({ ok: true, data, effects: [], error: null })
        const fail = (code: string, message?: string) => ({
          ok: false,
          data: null,
          effects: [],
          error: { code, message },
        })
        try {
          switch (action) {
            case 'host.kv.get': {
              const lookupDocId = payload?.docId ?? docId
              const key = payload?.key
              const tok = payload?.token ?? token ?? undefined
              if (!lookupDocId || typeof key !== 'string' || !key) {
                return fail('BAD_REQUEST', 'docId and key required')
              }
              const data = await getPluginKv(item.id, lookupDocId, key, tok)
              return ok(data)
            }
            default:
              return fail('UNSUPPORTED_ACTION', `Unsupported host action: ${action}`)
          }
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err)
          return fail('HOST_ACTION_FAILED', message)
        }
      },
      api: {
        getKv: (pluginId: string, docId2: string, key: string, tok?: string) =>
          getPluginKv(pluginId, docId2, key, tok),
      },
    }

    let route = `/document/${docId}`
    if (typeof mod.getRoute === 'function') {
      try {
        const docType = options.document?.type ?? null
        const res = await mod.getRoute(docId, {
          token,
          origin: apiOrigin,
          host: detectionHost,
          source: options.source ?? 'primary',
          document: options.document,
          docType: docType ?? undefined,
        })
        if (typeof res === 'string' && res) route = res
      } catch {
        /* noop */
      }
    }

    const routeWithToken = applyShareTokenToRoute(route, token)
    route = routeWithToken.route

    let canOpen = true
    if (typeof mod.canOpen === 'function') {
      try {
        const docType = options.document?.type ?? null
        canOpen = await mod.canOpen(docId, {
          token,
          origin: apiOrigin,
          host: detectionHost,
          source: options.source ?? 'primary',
          document: options.document,
          docType: docType ?? undefined,
        })
      } catch {
        canOpen = false
      }
    }

    const mounts = Array.isArray(item.mounts) ? item.mounts : []
    const currentPath = getCurrentPathname()
    const locationMatches = currentPath ? mounts.some((mount) => matchesMount(mount, currentPath)) : false

    if (!canOpen && !locationMatches) continue

    let routeToken: string | null = routeWithToken.token
    try {
      const url = new URL(route, window.location.origin)
      routeToken = routeToken ?? url.searchParams.get('token')
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

function extractTokenFromPath(path: string): string | null {
  if (!path) return null
  const idx = path.indexOf('?')
  if (idx === -1) return null
  const query = path.slice(idx + 1)
  try {
    const search = new URLSearchParams(query)
    const value = search.get('token')
    return value && value.trim().length > 0 ? value : null
  } catch {
    return null
  }
}

export async function mountResolvedPlugin(
  match: DocumentPluginMatch,
  container: HTMLElement,
  mode: 'primary' | 'secondary',
  options: { tweakHost?: (host: any) => void } = {},
) {
  const host = await createPluginHost(match.manifest, {
    docId: match.docId,
    route: match.route,
    token: match.token ?? undefined,
    mode,
  })
  try {
    options.tweakHost?.(host)
  } catch {
    /* noop */
  }

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
  options: {
    navigate?: (to: string) => void | Promise<void>
    setDocumentId?: (id?: string | null) => void
    setDocumentTitle?: (title?: string | null) => void
    setDocumentStatus?: (status?: string | null) => void
    setDocumentBadge?: (badge?: string | null) => void
    setDocumentActions?: (actions: DocumentHeaderAction[]) => void
  } = {},
) {
  const { navigate, setDocumentId, setDocumentTitle, setDocumentStatus, setDocumentBadge, setDocumentActions } = options
  const host = await createPluginHost(match.manifest, {
    mode: 'primary',
    navigate,
    setDocumentTitle,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
  })
  try {
    ;(match.module as any).__host__ = host
  } catch {
    /* noop */
  }

  try { setDocumentId?.(host?.context?.docId ?? null) } catch {}
  try { setDocumentStatus?.(undefined) } catch {}
  try { setDocumentBadge?.(undefined) } catch {}
  try { setDocumentActions?.([]) } catch {}

  const defaultTitle = match.manifest.name ?? match.manifest.id
  if (defaultTitle) {
    try {
      setDocumentTitle?.(defaultTitle)
    } catch {}
  }

  const dispose = await Promise.resolve(match.module?.default?.(container, host))
  return typeof dispose === 'function'
    ? () => {
        try {
          dispose()
        } catch {
          /* noop */
        }
        try { setDocumentId?.(undefined) } catch {}
        try { setDocumentTitle?.(undefined) } catch {}
        try { setDocumentStatus?.(undefined) } catch {}
        try { setDocumentBadge?.(undefined) } catch {}
        try { setDocumentActions?.([]) } catch {}
      }
    : () => {
        try { setDocumentId?.(undefined) } catch {}
        try { setDocumentTitle?.(undefined) } catch {}
        try { setDocumentStatus?.(undefined) } catch {}
        try { setDocumentBadge?.(undefined) } catch {}
        try { setDocumentActions?.([]) } catch {}
      }
}
