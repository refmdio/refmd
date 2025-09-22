"use client"

import { X, Loader2 } from 'lucide-react'
import { useEffect, useRef, useState, type MutableRefObject } from 'react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'

import { PreviewPane } from '@/features/edit-document'
import {
  matchesMount,
  mountResolvedPlugin,
  type DocumentPluginMatch,
} from '@/features/plugins'
import {
  type SecondaryViewerItemType,
  useSecondaryViewerContent,
} from '@/features/secondary-viewer'

type Props = {
  documentId: string | null
  documentType?: SecondaryViewerItemType
  className?: string
  onClose?: () => void
  onDocumentChange?: (id: string, type?: SecondaryViewerItemType) => void
}

export function SecondaryViewer({
  documentId,
  documentType = 'document',
  className,
  onClose,
  onDocumentChange,
}: Props) {
  const {
    content,
    error,
    currentType,
    isInitialLoading,
    pluginMatch,
    setError,
  } = useSecondaryViewerContent(documentId, documentType)

  const pluginContainerRef = useRef<HTMLDivElement | null>(null)
  const pluginDisposeRef = useRef<null | (() => void)>(null)
  const previousRouteRef = useRef<string | null>(null)
  const [pluginLoading, setPluginLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    let shouldRestoreRoute = false
    const container = pluginContainerRef.current

    if (!pluginMatch || !documentId) {
      if (pluginDisposeRef.current) {
        try {
          pluginDisposeRef.current()
        } catch {
          /* noop */
        }
        pluginDisposeRef.current = null
      }
      cleanupPlugin(container)
      setPluginLoading(false)
      return
    }

    if (!container) return

    container.innerHTML = ''
    setPluginLoading(true)
    setError(null)

    ;(async () => {
      shouldRestoreRoute = ensurePluginRoute(pluginMatch, previousRouteRef)

      try {
        const dispose = await mountResolvedPlugin(pluginMatch, container, 'secondary')
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
        pluginDisposeRef.current = dispose
      } catch (err: any) {
        if (!cancelled) {
          console.error('[plugins] secondary viewer mount failed', err)
          setError(err?.message || 'Failed to load plugin view')
        }
      } finally {
        if (!cancelled) {
          setPluginLoading(false)
        }
      }
    })()

    return () => {
      cancelled = true
      if (shouldRestoreRoute && previousRouteRef.current != null) {
        try {
          window.history.replaceState({}, '', previousRouteRef.current)
        } catch {
          /* noop */
        }
        previousRouteRef.current = null
      } else if (!shouldRestoreRoute) {
        previousRouteRef.current = null
      }

      if (pluginDisposeRef.current) {
        try {
          pluginDisposeRef.current()
        } catch {
          /* noop */
        }
        pluginDisposeRef.current = null
      }

      cleanupPlugin(container)
    }
  }, [documentId, pluginMatch, setError])

  if (!documentId) return null

  const loading = isInitialLoading || (currentType === 'plugin' && pluginLoading)

  return (
    <div className={cn('flex flex-col h-full min-h-0 relative', className)}>
      {onClose && (
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="absolute top-2 right-2 h-8 w-8 z-50"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
      <div className="flex-1 relative min-h-0 overflow-hidden">
        <div className="flex h-full min-h-0 flex-col">
          {error ? (
            <div className="p-4 text-center text-destructive">{error}</div>
          ) : currentType === 'plugin' ? (
            <>
              <div ref={pluginContainerRef} className="flex-1 min-h-0 overflow-auto" />
              {loading && (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-background/80">
                  <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  <p className="text-xs text-muted-foreground">Preparing plugin…</p>
                </div>
              )}
            </>
          ) : loading ? (
            <div className="flex flex-1 items-center justify-center p-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : currentType === 'scrap' ? (
            <div className="p-6 text-sm text-muted-foreground">Scrap preview is not supported yet.</div>
          ) : (
            <div className="flex flex-1 min-h-0 flex-col">
              <PreviewPane
                content={content}
                viewMode="preview"
                isSecondaryViewer
                documentIdOverride={documentId || undefined}
                onNavigate={(id) => onDocumentChange?.(id, 'document')}
                taskToggleDisabled
              />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default SecondaryViewer

function cleanupPlugin(container: HTMLDivElement | null) {
  if (!container) return
  try {
    container.innerHTML = ''
  } catch {
    /* noop */
  }
}

function ensurePluginRoute(
  match: DocumentPluginMatch,
  previousRouteRef: MutableRefObject<string | null>,
) {
  if (typeof window === 'undefined') return false

  const mounts = Array.isArray(match.manifest?.mounts) ? match.manifest.mounts : []
  const currentPath = (() => {
    try {
      return window.location.pathname
    } catch {
      return null
    }
  })()
  if (!currentPath) return false

  const isOnMount = mounts.some((mount) => matchesMount(mount, currentPath))
  if (!isOnMount) return false

  let target: URL
  try {
    target = new URL(match.route, window.location.origin)
  } catch {
    return false
  }

  const currentFull = (() => {
    try {
      return window.location.pathname + window.location.search + window.location.hash
    } catch {
      return null
    }
  })()
  const targetFull = `${target.pathname}${target.search}${target.hash}`
  if (!currentFull || currentFull === targetFull) return false

  if (previousRouteRef.current == null) {
    previousRouteRef.current = currentFull
  }

  try {
    window.history.replaceState({}, '', target.toString())
    return true
  } catch {
    return false
  }
}
