"use client"

import { toast } from 'sonner'

import {
  PluginsService,
  MarkdownService,
  DocumentsService,
  FilesService,
  AuthService,
  OpenAPI,
  type ManifestItem,
} from '@/shared/api/client'

import type { PluginChromeController, PluginChromeApi } from './chrome'

export type HostMode = 'primary' | 'secondary'

export type PluginHostContext = {
  docId?: string | null
  route?: string | null
  token?: string | null
  mode: HostMode
  navigate?: (to: string) => void | Promise<void>
  chrome?: PluginChromeController | null
}

const pluginModuleCache = new Map<string, Promise<any>>()
let sharedYjsImport: Promise<any> | null = null
let sharedYWebsocketImport: Promise<any> | null = null

export function getApiOrigin() {
  // OpenAPI client is the source of truth
  const base = OpenAPI && typeof OpenAPI.BASE === 'string' ? OpenAPI.BASE : ''
  if (base) {
    try {
      return new URL(base).origin
    } catch {
      // fall through to window-origin detection
    }
  }
  if (typeof window !== 'undefined') {
    try {
      return window.location.origin
    } catch {
      return ''
    }
  }
  return ''
}

export function extractDocIdFromRoute(route?: string | null) {
  if (!route) return null
  const noHash = route.split('#')[0] || ''
  if (/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(noHash)) {
    try {
      const parsed = new URL(noHash)
      const match = parsed.pathname.match(/([0-9a-fA-F-]{36})(?:$|[?/])/)
      if (match) return match[1]
      const segments = parsed.pathname.split('/').filter(Boolean)
      if (segments.length > 0) return segments[segments.length - 1]
    } catch {}
  }
  const pathPart = (() => {
    const idx = noHash.indexOf('?')
    return idx === -1 ? noHash : noHash.slice(0, idx)
  })()
  if (pathPart) {
    const match = pathPart.match(/([0-9a-fA-F-]{36})(?:$|[\/])/)
    if (match) return match[1]
    const segments = pathPart.split('/').filter(Boolean)
    if (segments.length > 0) return segments[segments.length - 1]
  }
  return null
}

export async function createPluginHost(manifest: ManifestItem, ctx: PluginHostContext) {
  const fallbackRoute = ctx.route ?? getWindowRoute()
  const resolvedDocId = ctx.docId ?? (fallbackRoute ? extractDocIdFromRoute(fallbackRoute) : null)
  const resolvedToken = ctx.token ?? (fallbackRoute ? extractQueryParam(fallbackRoute, 'token') : null)
  const apiOrigin = getApiOrigin()
  const fallbackNavigate = (to: string) => {
    if (!to) return
    const nav = (window as any).router?.navigate
    if (typeof nav === 'function') {
      try {
        nav({ to })
        return
      } catch {}
    }
    window.location.href = to
  }
  const performNavigate = (to: string) => {
    if (!to) return
    if (ctx.navigate) {
      try {
        const result = ctx.navigate(to)
        if (result && typeof (result as Promise<void>).catch === 'function') {
          ;(result as Promise<void>).catch(() => fallbackNavigate(to))
        }
        return
      } catch {
        fallbackNavigate(to)
        return
      }
    }
    fallbackNavigate(to)
  }
  const chromeApi: PluginChromeApi | undefined = ctx.chrome
    ? {
        setTitle: (value?: string | null) => ctx.chrome?.setTitle?.(value ?? ''),
        setStatus: (value?: string | null) => ctx.chrome?.setStatus?.(value ?? ''),
        setDocBadge: (value?: string | null) => ctx.chrome?.setDocBadge?.(value ?? ''),
        setActions: (actions) => ctx.chrome?.setActions?.(actions ?? []),
        reset: () => ctx.chrome?.reset?.(),
      }
    : undefined

  const host = {
    exec: async (action: string, args: any = {}) => {
      const json = await PluginsService.pluginsExecAction({
        plugin: manifest.id,
        action,
        requestBody: { payload: args },
      })
      if (json?.effects) applyEffects(json.effects, performNavigate)
      return json
    },
    navigate: performNavigate,
    toast: (level: string, message: string) => {
      const fn = (toast as any)[level]
      if (typeof fn === 'function') fn(message)
      else toast(message)
    },
    origin: apiOrigin,
    api: {
      me: () => AuthService.me(),
      renderMarkdown: (text: string, options: any) =>
        MarkdownService.renderMarkdown({ requestBody: { text, options } }),
      renderMarkdownMany: (items: Array<{ text: string; options: any }>) =>
        MarkdownService.renderMarkdownMany({ requestBody: { items } }),
      listRecords: (pluginId: string, docId: string, kind: string, token?: string) =>
        PluginsService.listRecords({ plugin: pluginId, docId, kind, token }),
      createRecord: (pluginId: string, docId: string, kind: string, data: any, token?: string) =>
        PluginsService.pluginsCreateRecord({
          plugin: pluginId,
          docId,
          kind,
          requestBody: { data },
          token,
        }),
      patchRecord: (pluginId: string, id: string, patch: any) =>
        PluginsService.pluginsUpdateRecord({ plugin: pluginId, id, requestBody: { patch } }),
      deleteRecord: (pluginId: string, id: string) => PluginsService.pluginsDeleteRecord({ plugin: pluginId, id }),
      getKv: (pluginId: string, docId: string, key: string, token?: string) =>
        PluginsService.pluginsGetKv({ plugin: pluginId, docId, key, token }),
      putKv: (pluginId: string, docId: string, key: string, value: any, token?: string) =>
        PluginsService.pluginsPutKv({ plugin: pluginId, docId, key, requestBody: { value }, token }),
      createDocument: (title: string, parentId?: string | null, type?: string) =>
        DocumentsService.createDocument({ requestBody: { title, parent_id: parentId as any, type } }),
      uploadFile: (docId: string, file: File) =>
        FilesService.uploadFile({ formData: { document_id: docId, file } as any }),
    },
    ui: {
      hydrateAttachments: async (root: Element) => {
        if (!root) return
        const wc = await import('@/entities/document/wc')
        try {
          wc.upgradeAttachments(root)
        } catch {}
      },
      hydrateWikiLinks: async (root: Element) => {
        if (!root) return
        const wc = await import('@/entities/document/wc')
        try {
          wc.upgradeWikiLinks(root)
        } catch {}
      },
      hydrateAll: async (root: Element) => {
        if (!root) return
        const wc = await import('@/entities/document/wc')
        try {
          wc.upgradeAll(root)
        } catch {}
      },
    },
    dependencies: {
      yjs: () => loadHostYjs(),
      yWebsocket: () => loadHostYWebsocket(),
    },
    chrome: chromeApi,
    context: {
      docId: resolvedDocId ?? null,
      route: fallbackRoute ?? null,
      token: resolvedToken ?? null,
      mode: ctx.mode,
    },
  }
  return host
}

export async function loadPluginModule(manifest: ManifestItem) {
  const frontend = manifest?.frontend as { entry?: string } | undefined
  const entry = frontend?.entry?.trim()
  if (!entry) return null
  const key = `${manifest.id}:${manifest.version || 'dev'}:${entry}`
  if (!pluginModuleCache.has(key)) {
    const versionTag = manifest.version || 'dev'
    const apiOrigin = getApiOrigin()
    const windowOrigin =
      typeof window !== 'undefined'
        ? (() => {
            try {
              return window.location.origin
            } catch {
              return undefined
            }
          })()
        : undefined
    const baseOrigin = apiOrigin || windowOrigin

    const buildUrl = (raw: string, base?: string) => {
      const url = base ? new URL(raw, base) : new URL(raw)
      try {
        url.searchParams.set('v', versionTag)
      } catch {}
      return url.toString()
    }

    const candidateUrls = (() => {
      const list: string[] = []
      const seen = new Set<string>()
      const push = (raw: string, base?: string) => {
        try {
          const value = buildUrl(raw, base)
          if (!seen.has(value)) {
            seen.add(value)
            list.push(value)
          }
        } catch {}
      }

      const trimmed = entry.trim()
      if (/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmed)) {
        push(trimmed)
      } else {
        if (baseOrigin) push(trimmed, baseOrigin)
        if (!trimmed.startsWith('/')) {
          push(`/${trimmed}`, baseOrigin)
        }
        const normalized = trimmed.startsWith('/') ? trimmed : `/${trimmed}`
        if (baseOrigin && normalized.startsWith('/plugins/')) {
          const assetPath = normalized.replace('/plugins/', '/api/plugin-assets/')
          push(assetPath, baseOrigin)
        }
      }
      return list
    })()

    if (candidateUrls.length === 0) {
      pluginModuleCache.set(
        key,
        Promise.reject(new Error('Unable to resolve plugin module URL')),
      )
    } else {
      const loader = (async () => {
        let lastError: unknown
        for (const url of candidateUrls) {
          try {
            return await import(/* @vite-ignore */ url)
          } catch (error) {
            lastError = error
            // Retry with next candidate if available
          }
        }
        throw lastError ?? new Error('Failed to resolve plugin module URL')
      })()

      pluginModuleCache.set(key, loader)
    }
  }

  try {
    return await pluginModuleCache.get(key)!
  } catch (err) {
    pluginModuleCache.delete(key)
    throw err
  }
}

export function clearPluginModuleCache() {
  pluginModuleCache.clear()
}

function getWindowRoute() {
  if (typeof window === 'undefined') return null
  try {
    return window.location.pathname + window.location.search + window.location.hash
  } catch {
    return null
  }
}

function extractQueryParam(route: string, key: string) {
  const noHash = route.split('#')[0] || ''
  const idx = noHash.indexOf('?')
  if (idx === -1) return null
  const query = noHash.slice(idx + 1)
  try {
    const value = new URLSearchParams(query).get(key)
    return value != null && value !== '' ? value : null
  } catch {
    return null
  }
}

function applyEffects(effects: any[], navigate?: (to: string) => void) {
  for (const effect of effects || []) {
    if (!effect || typeof effect !== 'object') continue
    if (effect.type === 'navigate' && typeof effect.to === 'string') {
      if (navigate) {
        navigate(effect.to)
      } else {
        try {
          window.history.pushState({}, '', effect.to)
          window.dispatchEvent(new PopStateEvent('popstate'))
        } catch {
          window.location.href = effect.to
        }
      }
    }
    if (effect.type === 'showToast' && typeof effect.message === 'string') {
      const level = effect.level || 'info'
      if (level === 'success') toast.success(effect.message)
      else if (level === 'warn' || level === 'warning')
        toast.warning?.(effect.message) || toast(effect.message)
      else if (level === 'error') toast.error(effect.message)
      else toast(effect.message)
    }
  }
}

async function loadHostYjs() {
  if (!sharedYjsImport) {
    sharedYjsImport = import('yjs')
  }
  return sharedYjsImport
}

async function loadHostYWebsocket() {
  if (!sharedYWebsocketImport) {
    sharedYWebsocketImport = import('y-websocket')
  }
  return sharedYWebsocketImport
}
