"use client"

import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

import type { ViewMode } from '@/shared/types/view-mode'

import { useAuthContext } from '@/features/auth'
import { EditorOverlay, MarkdownEditor, useCollaborativeDocument } from '@/features/edit-document'
import type { PreviewPaneProps } from '@/features/edit-document/ui/PreviewPane'

export type SplitEditorPreviewDelegateResult = {
  update?: (payload: { content: string; viewMode: ViewMode }) => void
  dispose?: () => void
}

export type SplitEditorPreviewDelegate = (ctx: {
  container: HTMLElement
  docId: string
  token?: string | null
  host: any
}) => SplitEditorPreviewDelegateResult | void

export type SplitEditorDocumentApi = {
  docId: string
  token?: string | null
  getContent: () => string
  setContent: (value: string) => void
}

export type SplitEditorStageOptions = {
  docId?: string | null
  token?: string | null
  host: any
  previewDelegate?: SplitEditorPreviewDelegate
  onDocumentReady?: (api: SplitEditorDocumentApi) => void | (() => void)
  variant?: 'full' | 'preview'
}

type MountRecord = {
  id: string
  container: HTMLElement
  options: SplitEditorStageOptions
  stopAutoCleanup?: () => void
}

const activeMounts = new Map<string, MountRecord>()
const listeners = new Set<() => void>()

const emit = () => {
  listeners.forEach((listener) => {
    try {
      listener()
    } catch {
      /* noop */
    }
  })
}

function makeMountId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return `mount:${crypto.randomUUID()}`
  return `mount:${Date.now()}:${Math.random().toString(36).slice(2)}`
}

function startAutoCleanup(id: string, container: HTMLElement) {
  if (typeof window === 'undefined') return undefined
  if (typeof document === 'undefined') return undefined

  let stopped = false
  let observer: MutationObserver | null = null
  let intervalId: number | null = null

  const stop = () => {
    if (stopped) return
    stopped = true
    if (intervalId != null) {
      try {
        window.clearInterval(intervalId)
      } catch {}
      intervalId = null
    }
    try {
      observer?.disconnect()
    } catch {}
    observer = null
  }

  const pruneIfDisconnected = () => {
    if (stopped) return
    if (container.isConnected) return
    stop()
    activeMounts.delete(id)
    emit()
  }

  if ('MutationObserver' in window && document.body) {
    observer = new MutationObserver(() => pruneIfDisconnected())
    try {
      observer.observe(document.body, { childList: true, subtree: true })
    } catch {
      // ignore
    }
  } else {
    intervalId = window.setInterval(pruneIfDisconnected, 1000)
  }

  return stop
}

export function mountSplitEditorStage(container: HTMLElement, options: SplitEditorStageOptions) {
  const id = makeMountId()
  const stopAutoCleanup = startAutoCleanup(id, container)
  activeMounts.set(id, { id, container, options, stopAutoCleanup })
  emit()
  return () => {
    const record = activeMounts.get(id)
    record?.stopAutoCleanup?.()
    activeMounts.delete(id)
    emit()
  }
}

export function mountSplitEditorPreviewStage(container: HTMLElement, options: Omit<SplitEditorStageOptions, 'variant'>) {
  return mountSplitEditorStage(container, { ...options, variant: 'preview' })
}

function useSplitEditorMounts() {
  const [, forceUpdate] = useState(0)
  useEffect(() => {
    let queued = false
    const listener = () => {
      if (queued) return
      queued = true
      const run = () => {
        queued = false
        forceUpdate((n) => n + 1)
      }
      if (typeof queueMicrotask === 'function') {
        queueMicrotask(run)
      } else {
        Promise.resolve().then(run)
      }
    }
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  }, [])
  return Array.from(activeMounts.values())
}

export function SplitEditorPortalRenderer() {
  const mounts = useSplitEditorMounts()
  useEffect(() => {
    let changed = false
    for (const [id, mount] of activeMounts) {
      if (!mount.container || !mount.container.isConnected) {
        mount.stopAutoCleanup?.()
        activeMounts.delete(id)
        changed = true
      }
    }
    if (changed) emit()
  }, [mounts.length])
  if (mounts.length === 0) return null
  return (
    <>
      {mounts.map((mount) => {
        if (!mount.container || !mount.container.isConnected) {
          return null
        }
        return createPortal(
          mount.options.variant === 'preview' ? (
            <PluginSplitPreviewStage key={mount.id} {...mount.options} />
          ) : (
            <PluginSplitEditorStage key={mount.id} {...mount.options} />
          ),
          mount.container,
        )
      })}
    </>
  )
}

function PluginSplitEditorStage({ docId, token, host, previewDelegate, onDocumentReady }: SplitEditorStageOptions) {
  if (!docId) {
    return (
      <div className="flex h-full flex-1 flex-col items-center justify-center p-6 text-sm text-muted-foreground">
        No document selected.
      </div>
    )
  }
  return (
    <PluginSplitEditorStageInner
      docId={docId}
      token={token ?? null}
      host={host}
      previewDelegate={previewDelegate}
      onDocumentReady={onDocumentReady}
    />
  )
}

function PluginSplitPreviewStage({ docId, token, host, previewDelegate, onDocumentReady }: SplitEditorStageOptions) {
  if (!docId) {
    return (
      <div className="flex h-full flex-1 flex-col items-center justify-center p-6 text-sm text-muted-foreground">
        No document selected.
      </div>
    )
  }
  return (
    <PluginSplitPreviewStageInner
      docId={docId}
      token={token ?? null}
      host={host}
      previewDelegate={previewDelegate}
      onDocumentReady={onDocumentReady}
    />
  )
}

type StageInnerProps = {
  docId: string
  token: string | null
  host: any
  previewDelegate?: SplitEditorPreviewDelegate
  onDocumentReady?: (api: SplitEditorDocumentApi) => void | (() => void)
}

function useDocContent(doc: any) {
  const [text, setText] = useState<string>('')
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (!doc) {
      setText('')
      return
    }
    let ytext: any = null
    try {
      ytext = doc.getText('content')
      setText(String(ytext.toString?.() ?? ''))
    } catch {
      setText('')
      ytext = null
    }
    if (!ytext) return

    const onUpdate = () => {
      if (rafRef.current != null) return
      rafRef.current = window.requestAnimationFrame(() => {
        rafRef.current = null
        try {
          setText(String(ytext.toString?.() ?? ''))
        } catch {
          setText('')
        }
      })
    }

    try {
      ytext.observe(onUpdate)
    } catch {
      /* noop */
    }

    return () => {
      try {
        ytext.unobserve(onUpdate)
      } catch {}
      if (rafRef.current != null) {
        try {
          window.cancelAnimationFrame(rafRef.current)
        } catch {}
        rafRef.current = null
      }
    }
  }, [doc])

  return text
}

function PluginSplitEditorStageInner({ docId, token, host, previewDelegate, onDocumentReady }: StageInnerProps) {
  const { user } = useAuthContext()
  const { status, doc, awareness, isReadOnly, error } = useCollaborativeDocument(docId, token ?? undefined, {
    contributeToRealtimeContext: false,
    useUrlShareTokenFallback: false,
    disablePersistence: true,
  })
  const [anonIdentity] = useState(() => {
    if (user) return null
    try {
      const keyName = 'refmd_anon_identity'
      const saved = localStorage.getItem(keyName)
      if (saved) return JSON.parse(saved) as { id: string; name: string }
      const rnd = Math.random().toString(36).slice(-4)
      const ident = { id: `guest:${rnd}`, name: `Guest-${rnd}` }
      localStorage.setItem(keyName, JSON.stringify(ident))
      return ident
    } catch {
      const rnd = Math.random().toString(36).slice(-4)
      return { id: `guest:${rnd}`, name: `Guest-${rnd}` }
    }
  })

  const shouldShowOverlay = Boolean(error) || !doc || !awareness
  const overlayLabel = error || (status === 'connecting' ? 'Connecting…' : 'Loading…')

  const renderPreview = previewDelegate
    ? (props: PreviewPaneProps) => (
        <PluginPreviewBridge
          {...props}
          delegate={previewDelegate}
          docId={docId}
          token={token}
          host={host}
        />
      )
    : undefined

  useEffect(() => {
    if (!doc || !onDocumentReady) return
    const ytext = doc.getText('content')
    const api: SplitEditorDocumentApi = {
      docId,
      token: token ?? undefined,
      getContent: () => String(ytext?.toString?.() ?? ''),
      setContent: (value: string) => {
        if (!ytext) return
        doc.transact(() => {
          try {
            const length = ytext.length
            ytext.delete(0, length)
            ytext.insert(0, value ?? '')
          } catch {
            /* noop */
          }
        })
      },
    }
    const cleanup = onDocumentReady(api)
    return () => {
      try { cleanup && cleanup() } catch {}
    }
  }, [doc, onDocumentReady, docId, token])

  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      {shouldShowOverlay && <EditorOverlay label={overlayLabel || 'Loading…'} />}
      {doc && awareness && !error && (
        <MarkdownEditor
          key={docId}
          doc={doc}
          awareness={awareness}
          connected={status === 'connected'}
          initialView="editor"
          userId={user?.id || anonIdentity?.id}
          userName={user?.name || anonIdentity?.name}
          documentId={docId}
          readOnly={isReadOnly}
          extraRight={undefined}
          renderPreview={renderPreview}
        />
      )}
    </div>
  )
}

function PluginSplitPreviewStageInner({ docId, token, host, previewDelegate, onDocumentReady }: StageInnerProps) {
  const { status, doc, error } = useCollaborativeDocument(docId, token ?? undefined, {
    contributeToRealtimeContext: false,
    useUrlShareTokenFallback: false,
    disablePersistence: true,
  })

  const shouldShowOverlay = Boolean(error) || !doc
  const overlayLabel = error || (status === 'connecting' ? 'Connecting…' : 'Loading…')

  const content = useDocContent(doc)

  useEffect(() => {
    if (!doc || !onDocumentReady) return
    const ytext = doc.getText('content')
    const api: SplitEditorDocumentApi = {
      docId,
      token: token ?? undefined,
      getContent: () => String(ytext?.toString?.() ?? ''),
      setContent: (value: string) => {
        if (!ytext) return
        doc.transact(() => {
          try {
            const length = ytext.length
            ytext.delete(0, length)
            ytext.insert(0, value ?? '')
          } catch {
            /* noop */
          }
        })
      },
    }
    const cleanup = onDocumentReady(api)
    return () => {
      try {
        cleanup && cleanup()
      } catch {}
    }
  }, [doc, onDocumentReady, docId, token])

  return (
    <div className="relative flex h-full flex-1 min-h-0 flex-col">
      {shouldShowOverlay && <EditorOverlay label={overlayLabel || 'Loading…'} />}
      {!previewDelegate ? (
        <div className="flex h-full flex-1 flex-col items-center justify-center p-6 text-sm text-muted-foreground">
          No preview delegate provided.
        </div>
      ) : doc && !error ? (
        <PluginPreviewBridge
          delegate={previewDelegate}
          docId={docId}
          token={token ?? null}
          host={host}
          content={content}
          viewMode="preview"
        />
      ) : null}
    </div>
  )
}

type PreviewBridgeProps = PreviewPaneProps & {
  delegate: SplitEditorPreviewDelegate
  docId: string
  token: string | null
  host: any
}

function PluginPreviewBridge({ delegate, docId, token, host, content, viewMode = 'preview' }: PreviewBridgeProps) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const delegateRef = useRef<SplitEditorPreviewDelegateResult | null>(null)
  const contextKey = useMemo(() => `${docId}:${token ?? ''}`, [docId, token])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const result = delegate({
      container,
      docId,
      token,
      host,
    })
    delegateRef.current = result || null
    return () => {
      try {
        delegateRef.current?.dispose?.()
      } catch {
        /* noop */
      }
      delegateRef.current = null
    }
  }, [delegate, contextKey, host])

  useEffect(() => {
    delegateRef.current?.update?.({ content, viewMode })
  }, [content, viewMode])

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div ref={containerRef} className="flex-1 min-h-0" />
    </div>
  )
}
