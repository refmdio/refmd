"use client"

import { toast } from 'sonner'

import {
  renderMarkdown,
  renderMarkdownMany,
  uploadFile,
  me as fetchMe,
  OpenAPI,
  type ManifestItem,
} from '@/shared/api'
import type { DocumentHeaderAction } from '@/shared/types/document'

import {
  createPluginRecord as apiCreatePluginRecord,
  deletePluginRecord as apiDeletePluginRecord,
  execPluginAction as apiExecPluginAction,
  getPluginKv as apiGetPluginKv,
  listPluginRecords as apiListPluginRecords,
  putPluginKv as apiPutPluginKv,
  updatePluginRecord as apiUpdatePluginRecord,
} from '@/entities/plugin/api'

import {
  mountSplitEditorStage,
  type SplitEditorPreviewDelegate,
  type SplitEditorDocumentApi,
} from '@/features/plugins/ui/SplitEditorHost'

export type HostMode = 'primary' | 'secondary'

export type PluginHostContext = {
  docId?: string | null
  route?: string | null
  token?: string | null
  mode: HostMode
  navigate?: (to: string) => void | Promise<void>
  setDocumentTitle?: (title?: string | null) => void
  setDocumentStatus?: (status?: string | null) => void
  setDocumentBadge?: (badge?: string | null) => void
  setDocumentActions?: (actions: DocumentHeaderAction[]) => void
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

export function applyShareTokenToRoute(
  route: string,
  token?: string | null,
): { route: string; token: string | null } {
  const shareToken = typeof token === 'string' && token.trim().length > 0 ? token.trim() : null
  if (!route || !shareToken) return { route, token: shareToken }

  try {
    const isAbsolute = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(route)
    const baseOrigin = typeof window !== 'undefined' ? window.location.origin : undefined
    const url = isAbsolute
      ? new URL(route)
      : new URL(route, baseOrigin ?? 'http://localhost')

    if (isAbsolute && (!baseOrigin || url.origin !== baseOrigin)) {
      const existingExternalToken = url.searchParams.get('token')
      const effectiveExternalToken = existingExternalToken && existingExternalToken.trim().length > 0
        ? existingExternalToken.trim()
        : shareToken
      return { route, token: effectiveExternalToken }
    }

    const existingToken = url.searchParams.get('token')
    const effectiveToken = existingToken && existingToken.trim().length > 0
      ? existingToken.trim()
      : shareToken
    if (!existingToken) {
      url.searchParams.set('token', effectiveToken)
    }

    const normalized = isAbsolute
      ? (baseOrigin && url.origin === baseOrigin ? `${url.pathname}${url.search}${url.hash}` : url.toString())
      : `${url.pathname}${url.search}${url.hash}`

    return { route: normalized, token: effectiveToken }
  } catch {
    return { route, token: shareToken }
  }
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
  const withShareToken = (to: string) => applyShareTokenToRoute(to, resolvedToken).route
  const fallbackNavigate = (to: string) => {
    if (!to) return
    const target = withShareToken(to)
    const nav = (window as any).router?.navigate
    if (typeof nav === 'function') {
      try {
        nav({ to: target })
        return
      } catch {}
    }
    window.location.href = target
  }
  const performNavigate = (to: string) => {
    if (!to) return
    const target = withShareToken(to)
    if (ctx.navigate) {
      try {
        const result = ctx.navigate(target)
        if (result && typeof (result as Promise<void>).catch === 'function') {
          ;(result as Promise<void>).catch(() => fallbackNavigate(target))
        }
        return
      } catch {
        fallbackNavigate(target)
        return
      }
    }
    fallbackNavigate(target)
  }
  const host = {
    exec: async (action: string, args: any = {}) => {
      const hostHandled = await executeHostAction(action, args, {
        pluginId: manifest.id,
        docId: resolvedDocId,
        token: resolvedToken,
        navigate: performNavigate,
      })
      if (hostHandled) return hostHandled

      const json = await apiExecPluginAction(
        manifest.id,
        action,
        args,
        resolvedToken ?? undefined,
      )
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
      me: () => fetchMe(),
      renderMarkdown: (text: string, options: any) =>
        renderMarkdown({ requestBody: { text, options } }),
      renderMarkdownMany: (items: Array<{ text: string; options: any }>) =>
        renderMarkdownMany({ requestBody: { items } }),
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
      setDocumentTitle: (title?: string | null) => {
        try {
          ctx.setDocumentTitle?.(title ?? undefined)
        } catch {}
      },
      setDocumentStatus: (status?: string | null) => {
        try {
          ctx.setDocumentStatus?.(status ?? undefined)
        } catch {}
      },
      setDocumentBadge: (badge?: string | null) => {
        try {
          ctx.setDocumentBadge?.(badge ?? undefined)
        } catch {}
      },
      setDocumentActions: (actions: Array<{ id?: string; label?: string; onSelect?: () => void; disabled?: boolean; variant?: string }> | null | undefined) => {
        try {
          if (!ctx.setDocumentActions) return
          const normalized: DocumentHeaderAction[] = Array.isArray(actions)
            ? actions
                .filter((action) => action && typeof action.label === 'string')
                .map((action) => ({
                  id: action.id,
                  label: String(action.label),
                  onSelect: typeof action.onSelect === 'function' ? action.onSelect : undefined,
                  disabled: Boolean(action.disabled),
                  variant: action.variant === 'primary' ? 'primary' : action.variant === 'outline' ? 'outline' : 'default',
                }))
            : []
          ctx.setDocumentActions(normalized)
        } catch {}
      },
      mountSplitEditor: (container: Element, options?: {
        docId?: string | null
        token?: string | null
        preview?: { delegate?: SplitEditorPreviewDelegate }
        document?: { onReady?: (api: SplitEditorDocumentApi) => void | (() => void) }
      }) => {
        if (typeof window === 'undefined') return undefined
        if (!container) return undefined
        const target = container as HTMLElement
        const docId = options?.docId ?? resolvedDocId ?? null
        const token = options?.token ?? resolvedToken ?? null
        const delegate = options?.preview?.delegate
        if (!docId) {
          target.innerHTML = '<div class="p-4 text-sm text-muted-foreground">No document selected.</div>'
          return undefined
        }
        try {
          window.dispatchEvent(
            new CustomEvent<{ docId: string }>('refmd:plugin:uses-split-editor', {
              detail: { docId },
            }),
          )
        } catch {
          /* noop */
        }
        return mountSplitEditorStage(target, {
          docId,
          token,
          host,
          previewDelegate: delegate,
          onDocumentReady: options?.document?.onReady,
        })
      },
    },
    dependencies: {
      yjs: () => loadHostYjs(),
      yWebsocket: () => loadHostYWebsocket(),
    },
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

type HostActionContext = {
  pluginId: string
  docId: string | null
  token: string | null
  navigate: (to: string) => void
}

async function executeHostAction(
  action: string,
  args: any,
  ctx: HostActionContext,
): Promise<any | null> {
  const ok = (data: any) => ({ ok: true, data, effects: [], error: null })
  const fail = (code: string, message?: string) => ({
    ok: false,
    data: null,
    effects: [],
    error: { code, message },
  })

  const ensureDocId = (explicit?: string | null) => {
    const docId = explicit ?? ctx.docId
    if (!docId) throw fail('BAD_REQUEST', 'docId required')
    return docId
  }

  try {
    switch (action) {
      case 'host.records.list': {
        const docId = ensureDocId(args?.docId)
        const kind = args?.kind
        if (typeof kind !== 'string' || !kind) throw fail('BAD_REQUEST', 'kind required')
        const token = (args?.token ?? ctx.token) || undefined
        const response = await apiListPluginRecords(ctx.pluginId, docId, kind, token)
        return ok(response)
      }
      case 'host.records.create': {
        const docId = ensureDocId(args?.docId)
        const kind = args?.kind
        if (typeof kind !== 'string' || !kind) throw fail('BAD_REQUEST', 'kind required')
        const token = (args?.token ?? ctx.token) || undefined
        const response = await apiCreatePluginRecord(ctx.pluginId, docId, kind, args?.data ?? null, token)
        return ok(response)
      }
      case 'host.records.update': {
        const id = args?.id
        if (typeof id !== 'string' || !id) throw fail('BAD_REQUEST', 'record id required')
        const token = (args?.token ?? ctx.token) || undefined
        const response = await apiUpdatePluginRecord(ctx.pluginId, id, args?.patch ?? {}, token)
        return ok(response)
      }
      case 'host.records.delete': {
        const id = args?.id
        if (typeof id !== 'string' || !id) throw fail('BAD_REQUEST', 'record id required')
        const token = (args?.token ?? ctx.token) || undefined
        await apiDeletePluginRecord(ctx.pluginId, id, token)
        return ok({})
      }
      case 'host.kv.get': {
        const docId = ensureDocId(args?.docId)
        const key = args?.key
        if (typeof key !== 'string' || !key) throw fail('BAD_REQUEST', 'key required')
        const token = (args?.token ?? ctx.token) || undefined
        const response = await apiGetPluginKv(ctx.pluginId, docId, key, token)
        return ok(response)
      }
      case 'host.kv.put': {
        const docId = ensureDocId(args?.docId)
        const key = args?.key
        if (typeof key !== 'string' || !key) throw fail('BAD_REQUEST', 'key required')
        const value = args?.value ?? null
        const token = (args?.token ?? ctx.token) || undefined
        const response = await apiPutPluginKv(ctx.pluginId, docId, key, value, token)
        return ok(response)
      }
      case 'host.files.upload': {
        const docId = ensureDocId(args?.docId)
        const file: File | undefined = args?.file
        if (!(file instanceof File)) throw fail('BAD_REQUEST', 'file required')
        const response = await uploadFile({
          formData: { document_id: docId, file } as any,
        })
        return ok(response)
      }
      case 'host.navigate': {
        const to = args?.to
        if (typeof to !== 'string' || !to) throw fail('BAD_REQUEST', 'destination required')
        ctx.navigate(to)
        return ok({})
      }
      default:
        return null
    }
  } catch (err) {
    if (err && typeof err === 'object' && 'ok' in (err as any) && (err as any).ok === false) {
      return err
    }
    const message = err instanceof Error ? err.message : String(err)
    return fail('HOST_ACTION_FAILED', message)
  }
}
