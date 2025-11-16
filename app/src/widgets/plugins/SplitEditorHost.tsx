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
}

type MountRecord = {
  id: symbol
  container: HTMLElement
  options: SplitEditorStageOptions
}

const activeMounts = new Map<symbol, MountRecord>()
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

export function mountSplitEditorStage(container: HTMLElement, options: SplitEditorStageOptions) {
  const id = Symbol('split-editor')
  activeMounts.set(id, { id, container, options })
  emit()
  return () => {
    activeMounts.delete(id)
    emit()
    try {
      container.innerHTML = ''
    } catch {
      /* noop */
    }
  }
}

function useSplitEditorMounts() {
  const [, forceUpdate] = useState(0)
  useEffect(() => {
    const listener = () => forceUpdate((n) => n + 1)
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  }, [])
  return Array.from(activeMounts.values())
}

export function SplitEditorPortalRenderer() {
  const mounts = useSplitEditorMounts()
  if (mounts.length === 0) return null
  return (
    <>
      {mounts.map((mount) => {
        if (!mount.container || !mount.container.isConnected) {
          return null
        }
        return createPortal(
          <PluginSplitEditorStage key={String(mount.id)} {...mount.options} />,
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

type StageInnerProps = {
  docId: string
  token: string | null
  host: any
  previewDelegate?: SplitEditorPreviewDelegate
  onDocumentReady?: (api: SplitEditorDocumentApi) => void | (() => void)
}

function PluginSplitEditorStageInner({ docId, token, host, previewDelegate, onDocumentReady }: StageInnerProps) {
  const { user } = useAuthContext()
  const { status, doc, awareness, isReadOnly, error } = useCollaborativeDocument(docId, token ?? undefined)
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
          initialView="split"
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
    container.innerHTML = ''
    const result = delegate({
      container,
      docId,
      token,
      host,
    })
    delegateRef.current = result || null
    return () => {
      try {
        container.innerHTML = ''
      } catch {
        /* noop */
      }
      delegateRef.current?.dispose?.()
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
