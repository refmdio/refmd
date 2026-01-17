import { useCallback, useMemo, useRef } from 'react'
import { toast } from 'sonner'

import { API_BASE_URL } from '@/shared/lib/config'

import { handleEffects as handleEffectsFull } from '@/features/plugins/lib/effect-handler'
import { loadPluginWasm, hasPluginWasm } from '@/features/plugins/lib/wasm-loader'
import { getWasmRuntime } from '@/features/plugins/lib/wasm-runtime'
import { getKeyVaultService, fetchDocumentDek } from '@/features/security'

import { getPluginKv } from '../api'
import type { PluginManifestItem } from '../api'

type Options = {
  plugins: PluginManifestItem[]
  shareToken?: string | null
  workspaceId?: string | null
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

/**
 * Get document DEK for E2EE encryption.
 * Returns null if E2EE is not available or document has no DEK.
 */
async function getDocumentDEK(
  docId: string | null,
  workspaceId: string | null
): Promise<Uint8Array | null> {
  if (!docId || !workspaceId) return null

  try {
    const service = getKeyVaultService()
    if (!service.isInitialized || !service.isUnlocked) return null

    return await fetchDocumentDek(docId, workspaceId)
  } catch {
    // E2EE not available for this document
    return null
  }
}

export function usePluginExecutor({
  plugins,
  shareToken,
  workspaceId,
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

  const withShareToken = useCallback(
    (target: string) => {
      const token = typeof shareToken === 'string' && shareToken.trim().length > 0 ? shareToken.trim() : null
      if (!target || !token) return target
      try {
        const isAbsolute = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(target)
        const base = typeof window !== 'undefined' ? window.location.origin : undefined
        const url = isAbsolute ? new URL(target) : new URL(target, base ?? 'http://localhost')
        if (isAbsolute && (!base || url.origin !== base)) {
          return target
        }
        if (!url.searchParams.get('token')) {
          url.searchParams.set('token', token)
        }
        return isAbsolute
          ? (base && url.origin === base ? `${url.pathname}${url.search}${url.hash}` : url.toString())
          : `${url.pathname}${url.search}${url.hash}`
      } catch {
        return target
      }
    },
    [shareToken],
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
                return withShareToken(route)
              }
            }
          }
        } catch (err) {
          console.warn('[plugins] resolveDocRoute failed', plugin.id, err)
        }
      }
      const suffix = shareToken ? `?token=${encodeURIComponent(shareToken)}` : ''
      return withShareToken(`/document/${docId}${suffix}`)
    },
    [apiOrigin, importPluginModule, plugins, shareToken, withShareToken],
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
              exec: async (actionName: string, payload: any) => {
                const manifest = plugins.find((p) => p.id === pluginId)
                if (!manifest) {
                  throw new Error(`Plugin ${pluginId} manifest not found`)
                }
                if (!hasPluginWasm(manifest)) {
                  throw new Error(`Plugin ${pluginId} has no WASM module`)
                }
                const runtime = getWasmRuntime()
                if (!runtime.isLoaded(pluginId)) {
                  const wasmUrl = await loadPluginWasm(pluginId, manifest)
                  await runtime.loadPlugin(pluginId, wasmUrl)
                }
                return runtime.execute(pluginId, actionName, payload, { docId: null, userId: null })
              },
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

          // Handle effects with full effect handler
          if (result?.effects && result.effects.length > 0) {
            // Get document DEK for E2EE encryption
            const effectDocId = selectedDocId || null
            const documentDEK = await getDocumentDEK(effectDocId, workspaceId ?? null)

            await handleEffectsFull(result.effects, {
              pluginId,
              docId: effectDocId,
              workspaceId: workspaceId ?? null,
              documentDEK,
              token: shareToken ?? null,
              navigate,
            })
          } else if (result?.ok === false && result?.error) {
            toast.error(result.error.message || result.error.code || 'Action failed')
          }
          refreshDocuments()
          return
        }

        // Fallback: use client-side WASM execution
        const manifest = plugins.find((p) => p.id === pluginId)
        if (!manifest) {
          toast.error(`Plugin ${pluginId} not found`)
          return
        }
        if (!hasPluginWasm(manifest)) {
          toast.error(`Plugin ${pluginId} has no executable module`)
          return
        }
        const runtime = getWasmRuntime()
        if (!runtime.isLoaded(pluginId)) {
          const wasmUrl = await loadPluginWasm(pluginId, manifest)
          await runtime.loadPlugin(pluginId, wasmUrl)
        }
        let response = await runtime.execute(pluginId, action, defaultPayload, { docId: null, userId: null })
        const errCode = response?.error?.code
        const errMsg = String(response?.error?.message || '')
        if (errCode === 'BAD_REQUEST' && errMsg.toLowerCase().includes('docid')) {
          const input = await resolveRequestDocumentId()
          if (input) {
            response = await runtime.execute(
              pluginId,
              action,
              { ...(defaultPayload || {}), docId: input },
              { docId: input, userId: null },
            )
          } else {
            toast.error('Select a document before running this command')
            return
          }
        }
        // Handle effects with full effect handler
        const effectDocId = selectedDocId || null
        if (response?.effects && response.effects.length > 0) {
          // Get document DEK for E2EE encryption
          const documentDEK = await getDocumentDEK(effectDocId, workspaceId ?? null)

          await handleEffectsFull(response.effects, {
            pluginId,
            docId: effectDocId,
            workspaceId: workspaceId ?? null,
            documentDEK,
            token: shareToken ?? null,
            navigate,
          })
        } else if (response?.ok === false && response?.error) {
          toast.error(response.error.message || response.error.code || 'Action failed')
        }
        refreshDocuments()
      } catch (err: any) {
        toast.error(err?.message || 'Failed to execute command')
      }
    },
    [apiOrigin, getCurrentDocumentId, importPluginModule, navigate, plugins, refreshDocuments, resolveRequestDocumentId, shareToken, workspaceId],
  )

  return { runPluginCommand, resolveDocRoute }
}
