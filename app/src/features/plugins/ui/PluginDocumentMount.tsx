"use client"

import { useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'

import { fetchDocumentMeta } from '@/entities/document'

import { mountSplitEditorPreviewStage } from '@/features/plugins/ui/SplitEditorHost'

import { mountResolvedPlugin, resolvePluginForDocumentById } from '../lib/resolution'

const PLUGIN_USES_SPLIT_EDITOR_EVENT = 'refmd:plugin:uses-split-editor'

export type PluginMountVariant = 'full' | 'preview'

export function PluginDocumentMount({
  docId,
  token,
  pluginIdHint,
  variant = 'full',
  mode = 'secondary',
  className,
}: {
  docId: string
  token?: string | null
  pluginIdHint?: string | null
  variant?: PluginMountVariant
  mode?: 'primary' | 'secondary'
  className?: string
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [mountError, setMountError] = useState<string | null>(null)

  const normalizedDocId = docId.trim()
  const normalizedHint = typeof pluginIdHint === 'string' ? pluginIdHint.trim() : ''
  const tokenKey = typeof token === 'string' ? token : ''

  const metaQuery = useQuery({
    queryKey: ['document-meta', normalizedDocId, token ?? null],
    queryFn: async () => fetchDocumentMeta(normalizedDocId, token ?? undefined),
    staleTime: 60_000,
    enabled: Boolean(normalizedDocId && !normalizedHint),
  })

  const resolvedPluginId = useMemo(() => {
    if (normalizedHint) return normalizedHint
    const raw = (metaQuery.data as any)?.created_by_plugin
    return typeof raw === 'string' && raw.trim() ? raw.trim() : ''
  }, [metaQuery.data, normalizedHint])

  const pluginQuery = useQuery({
    queryKey: ['plugin-document', normalizedDocId, resolvedPluginId, token ?? null],
    queryFn: async () => resolvePluginForDocumentById(normalizedDocId, resolvedPluginId, token ?? null),
    staleTime: 60_000,
    enabled: Boolean(normalizedDocId && resolvedPluginId),
  })

  const mountNodeKey = useMemo(() => {
    return `${normalizedDocId}:${resolvedPluginId || 'none'}:${variant}:${mode}:${tokenKey}`
  }, [mode, normalizedDocId, resolvedPluginId, tokenKey, variant])

  useEffect(() => {
    const container = containerRef.current
    const match = pluginQuery.data ?? null
    if (!container) return
    if (!match) {
      return
    }

    let disposed = false
    let dispose: (() => void) | null = null
    setMountError(null)

    ;(async () => {
      try {
        dispose = (await mountResolvedPlugin(
          match,
          container,
          mode,
          variant === 'preview'
            ? {
                tweakHost: (host) => {
                  if (!host || typeof host !== 'object') return
                  if (!host.ui || typeof host.ui !== 'object') host.ui = {}
                  ;(host.ui as any).mountSplitEditor = (target: Element, options?: any) => {
                    if (typeof window === 'undefined') return undefined
                    if (!target) return undefined
                    const el = target as HTMLElement
                    const previewDelegate = options?.preview?.delegate
                    const onDocumentReady = options?.document?.onReady
                    const nextDocId = options?.docId ?? host?.context?.docId ?? null
                    const nextToken = options?.token ?? host?.context?.token ?? null
                    if (typeof nextDocId === 'string' && nextDocId.trim()) {
                      try {
                        window.dispatchEvent(
                          new CustomEvent<{ docId: string }>(PLUGIN_USES_SPLIT_EDITOR_EVENT, {
                            detail: { docId: nextDocId.trim() },
                          }),
                        )
                      } catch {
                        /* noop */
                      }
                    }
                    return mountSplitEditorPreviewStage(el, {
                      docId: nextDocId,
                      token: nextToken,
                      host,
                      previewDelegate,
                      onDocumentReady,
                    })
                  }
                },
              }
            : {},
        )) as any
      } catch (err) {
        if (!disposed) {
          const message = err instanceof Error ? err.message : String(err)
          setMountError(message || 'Failed to mount plugin')
        }
      }
    })()

    return () => {
      disposed = true
      try {
        dispose?.()
      } catch {
        /* noop */
      }
    }
  }, [mode, mountNodeKey, pluginQuery.data, variant])

  if (!normalizedDocId) return null

  if (mountError) {
    return <div className="p-4 text-sm text-destructive">Failed to mount plugin: {mountError}</div>
  }

  if (pluginQuery.isPending || (metaQuery.isPending && !normalizedHint)) {
    return <div className="p-4 text-sm text-muted-foreground">Loading plugin…</div>
  }

  if (!resolvedPluginId) {
    return <div className="p-4 text-sm text-muted-foreground">No plugin assigned to this document.</div>
  }

  if (!pluginQuery.data) {
    if (pluginQuery.isError) {
      return <div className="p-4 text-sm text-destructive">Failed to resolve plugin.</div>
    }
    return <div className="p-4 text-sm text-muted-foreground">Plugin is not available.</div>
  }

  return (
    <div className={className ?? 'h-full w-full overflow-auto'}>
      <div key={mountNodeKey} ref={containerRef} className="h-full w-full" />
    </div>
  )
}
