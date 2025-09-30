import { useCallback, useMemo, useRef } from 'react'
import { toast } from 'sonner'

import { API_BASE_URL } from '@/shared/lib/config'

import { createDocument } from '@/entities/document'

import {
  createPluginRecord,
  execPluginAction,
  getPluginKv,
  putPluginKv,
} from '../api'
import type { PluginManifestItem } from '../api'

type Options = {
  plugins: PluginManifestItem[]
  shareToken?: string | null
  refreshDocuments: () => void
  navigate: (to: string) => void
  getCurrentDocumentId: () => string | null
  requestDocumentId?: () => Promise<string | null> | string | null
}

type PluginModule = {
  exec?: (action: string, ctx: { host: any; payload: any }) => Promise<any>
  canOpen?: (docId: string, ctx: { token?: string | null; origin: string; host: any }) => Promise<boolean>
  getRoute?: (docId: string, ctx: { token?: string | null; origin: string; host: any }) => Promise<string | null>
}

const uuidPattern = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/

export function usePluginExecutor({
  plugins,
  shareToken,
  refreshDocuments,
  navigate,
  getCurrentDocumentId,
  requestDocumentId,
}: Options) {
  const moduleCache = useRef(new Map<string, PluginModule | null>())
  const moduleCacheKeys = useRef(new Map<string, string>())

  const apiOrigin = useMemo(() => {
    try {
      return new URL(API_BASE_URL || '').origin
    } catch (err) {
      if (typeof window !== 'undefined') {
        return window.location.origin
      }
      return ''
    }
  }, [])

  const resolveRequestDocumentId = useCallback(async () => {
    if (!requestDocumentId) return null
    const resolver = requestDocumentId
    try {
      const result = typeof resolver === 'function' ? await resolver() : resolver
      if (typeof result !== 'string') return null
      const trimmed = result.trim()
      return uuidPattern.test(trimmed) ? trimmed : null
    } catch {
      return null
    }
  }, [requestDocumentId])

  const importPluginModule = useCallback(
    async (pluginId: string) => {
      const manifest = plugins.find((p) => p.id === pluginId && (p as any)?.scope === 'user')
        ?? plugins.find((p) => p.id === pluginId)
      if (!manifest) {
        moduleCacheKeys.current.delete(pluginId)
        return null
      }
      const entry = (manifest.frontend as any)?.entry
      if (!entry || typeof entry !== 'string') {
        moduleCacheKeys.current.delete(pluginId)
        return null
      }

      const version = (manifest as any)?.version ? String((manifest as any).version) : 'dev'
      const scope = (manifest as any)?.scope ? String((manifest as any).scope) : 'global'
      const cacheKey = `${manifest.id}:${version}:${scope}:${entry}`

      const cached = moduleCache.current.get(cacheKey)
      if (cached !== undefined) {
        return cached
      }

      const previousKey = moduleCacheKeys.current.get(pluginId)
      if (previousKey && previousKey !== cacheKey) {
        moduleCache.current.delete(previousKey)
      }
      moduleCacheKeys.current.set(pluginId, cacheKey)

      const url = new URL(entry, apiOrigin)
      try {
        const cacheBuster = version === 'dev' ? String(Date.now()) : version
        url.searchParams.set('v', cacheBuster)
      } catch {
        // ignore cache-busting failure
      }
      try {
        const mod: PluginModule = await import(/* @vite-ignore */ url.toString())
        moduleCache.current.set(cacheKey, mod)
        return mod
      } catch (err) {
        console.warn('[plugins] failed to import module', pluginId, err)
        moduleCache.current.set(cacheKey, null)
        return null
      }
    },
    [apiOrigin, plugins],
  )

  const resolveDocRoute = useCallback(
    async (docId: string) => {
      const ordered = [
        ...plugins.filter((p) => (p as any)?.scope === 'user'),
        ...plugins.filter((p) => (p as any)?.scope !== 'user'),
      ]
      for (const plugin of ordered) {
        try {
          const mod = await importPluginModule(plugin.id)
          if (mod && typeof mod.canOpen === 'function') {
            const host = {
              origin: apiOrigin,
              api: {
                getKv: (pluginId: string, docId2: string, key: string, token?: string) =>
                  getPluginKv(pluginId, docId2, key, token),
              },
            }
            const canOpen = await mod.canOpen(docId, { token: shareToken, origin: apiOrigin, host })
            if (canOpen && typeof mod.getRoute === 'function') {
              const route = await mod.getRoute(docId, { token: shareToken, origin: apiOrigin, host })
              if (typeof route === 'string' && route) {
                return route
              }
            }
          }
        } catch (err) {
          console.warn('[plugins] resolveDocRoute failed', plugin.id, err)
        }
      }
      const suffix = shareToken ? `?token=${encodeURIComponent(shareToken)}` : ''
      return `/document/${docId}${suffix}`
    },
    [apiOrigin, importPluginModule, plugins, shareToken],
  )

  const runPluginCommand = useCallback(
    async (pluginId: string, action: string) => {
      try {
        const selectedDocId = getCurrentDocumentId() || undefined
        const defaultPayload = selectedDocId ? { docId: selectedDocId } : {}

        const mod = await importPluginModule(pluginId)
        if (mod && typeof mod.exec === 'function') {
          const host = {
            origin: apiOrigin,
            navigate: (to: string) => {
              try {
                navigate(to)
              } catch (err) {
                console.warn('[plugins] navigate failed', err)
                if (typeof window !== 'undefined') window.location.href = to
              }
            },
            toast: (level: string, message: string) => {
              const fn = (toast as any)[level]
              if (typeof fn === 'function') fn(message)
              else toast(message)
            },
            api: {
              exec: (actionName: string, payload: any) =>
                execPluginAction(pluginId, actionName, payload),
              createDocument: (title: string, parentId?: string | null, type?: string) =>
                createDocument({ title, parent_id: parentId ?? null, type: type as any }),
              putKv: (pluginId2: string, docId2: string, key: string, value: any, token?: string) =>
                putPluginKv(pluginId2, docId2, key, value, token),
              createRecord: (pluginId2: string, docId2: string, kind: string, data: any, token?: string) =>
                createPluginRecord(pluginId2, docId2, kind, data, token),
            },
          }

          let result = await mod.exec(action, { host, payload: defaultPayload })
          if (
            result &&
            result.ok === false &&
            result.error &&
            result.error.code === 'BAD_REQUEST' &&
            String(result.error.message || '').toLowerCase().includes('docid')
          ) {
            const input = await resolveRequestDocumentId()
            if (input) {
              result = await mod.exec(action, {
                host,
                payload: { ...(defaultPayload || {}), docId: input },
              })
            } else {
              toast.error('Select a document before running this command')
              return
            }
          }

          handleEffects(result?.effects, navigate)
          if (!result?.effects || result.effects.length === 0) {
            toast.success('Action executed')
          }
          refreshDocuments()
          return
        }

        let response = await execPluginAction(pluginId, action, defaultPayload)
        const errCode = (response as any)?.error?.code
        const errMsg = String((response as any)?.error?.message || '')
        if (errCode === 'BAD_REQUEST' && errMsg.toLowerCase().includes('docid')) {
          const input = await resolveRequestDocumentId()
          if (input) {
            response = await execPluginAction(pluginId, action, { ...(defaultPayload || {}), docId: input })
          } else {
            toast.error('Select a document before running this command')
            return
          }
        }
        handleEffects(response?.effects, navigate)
        if (!response?.effects || response.effects.length === 0) {
          toast.success('Action executed')
        }
        refreshDocuments()
      } catch (err: any) {
        toast.error(err?.message || 'Failed to execute command')
      }
    },
    [apiOrigin, getCurrentDocumentId, importPluginModule, navigate, refreshDocuments, resolveRequestDocumentId],
  )

  return { runPluginCommand, resolveDocRoute }
}

function handleEffects(effects: any[], navigate: (to: string) => void) {
  if (!Array.isArray(effects)) return
  for (const effect of effects) {
    if (!effect || typeof effect !== 'object') continue
    if (effect.type === 'navigate' && typeof effect.to === 'string') {
      navigate(effect.to)
    } else if (effect.type === 'showToast' && typeof effect.message === 'string') {
      const level = effect.level || 'info'
      if (level === 'success') toast.success(effect.message)
      else if (level === 'warn' || level === 'warning') (toast as any).warning?.(effect.message) || toast(effect.message)
      else if (level === 'error') toast.error(effect.message)
      else toast(effect.message)
    }
  }
}
