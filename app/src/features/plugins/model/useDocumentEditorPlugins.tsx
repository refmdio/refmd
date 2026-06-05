"use client"

import { X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState, type MutableRefObject } from 'react'
import { toast as sonnerToast } from 'sonner'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { ScrollArea } from '@/shared/ui/scroll-area'

import {
  execPluginAction,
  getPluginKv,
  listPluginRecords,
} from '@/entities/plugin'

import { useAuthContext } from '@/features/auth'

import type {
  DocumentEditorActivationContext,
  DocumentEditorApi,
  DocumentEditorDocumentApi,
  DocumentEditorPaneContribution,
  DocumentEditorPaneRegistration,
  DocumentEditorPaneRenderContext,
  DocumentEditorPluginMatch,
  DocumentEditorUserApi,
  RegisteredDocumentEditorPane,
} from '../lib/document-editor'
import { renderDocumentPaneIcon } from '../lib/pane-icons'
import { resolveDocumentEditorPlugins } from '../lib/resolution'

type UseDocumentEditorPluginsArgs = {
  enabled: boolean
  document: DocumentEditorDocumentApi | null
  editor: DocumentEditorApi | null
  onPaneHostChange?: (host: DocumentEditorPaneHostState | null) => void
}

type ActiveListener = (active: boolean) => void

function scopePluginOwnerId(pluginId: string, ownerId: string) {
  return `${pluginId}:${String(ownerId || 'default')}`
}

function createScopedDocumentEditorApi(editor: DocumentEditorApi, pluginId: string): DocumentEditorApi {
  return {
    ...editor,
    setDecorations: (ownerId, decorations) =>
      editor.setDecorations(scopePluginOwnerId(pluginId, ownerId), decorations),
    setHiddenRanges: (ownerId, ranges) =>
      editor.setHiddenRanges(scopePluginOwnerId(pluginId, ownerId), ranges),
  }
}

function createInactivePaneRegistration(): DocumentEditorPaneRegistration {
  return {
    dispose: () => {},
    setBadge: () => {},
    setTitle: () => {},
    open: () => {},
  }
}

function resolveAnonymousDocumentEditorUser(): DocumentEditorUserApi | null {
  if (typeof window === 'undefined') return null
  try {
    const keyName = 'refmd_anon_identity'
    const existing = window.localStorage.getItem(keyName)
    if (existing) {
      const parsed = JSON.parse(existing) as Partial<DocumentEditorUserApi>
      if (typeof parsed.id === 'string' && typeof parsed.name === 'string') {
        return { id: parsed.id, name: parsed.name }
      }
    }
    const rnd = Math.random().toString(36).slice(2, 8)
    const identity = { id: `guest:${rnd}`, name: `Guest-${rnd}` }
    window.localStorage.setItem(keyName, JSON.stringify(identity))
    return identity
  } catch {
    const rnd = Math.random().toString(36).slice(2, 8)
    return { id: `guest:${rnd}`, name: `Guest-${rnd}` }
  }
}

function applyDocumentEditorActionEffects(effects: unknown) {
  if (!Array.isArray(effects)) return
  for (const effect of effects) {
    if (!effect || typeof effect !== 'object') continue
    const item = effect as any
    if (item.type === 'showToast') {
      const level = typeof item.level === 'string' ? item.level : 'info'
      const message = typeof item.message === 'string' ? item.message : ''
      if (!message) continue
      const fn = (sonnerToast as any)[level]
      if (typeof fn === 'function') fn(message)
      else sonnerToast(message)
      continue
    }
    if (item.type === 'navigate' && typeof item.to === 'string' && typeof window !== 'undefined') {
      window.location.href = item.to
    }
  }
}

export type DocumentEditorPaneHostState = {
  panes: RegisteredDocumentEditorPane[]
  activePaneKey: string | null
  document: DocumentEditorDocumentApi
  editor: DocumentEditorApi
  user: DocumentEditorUserApi | null
  openPane: (key: string) => void
  closePane: (key?: string | null) => void
  activeListenersRef: MutableRefObject<Map<string, Set<ActiveListener>>>
}

export function useDocumentEditorPlugins({
  enabled,
  document,
  editor,
  onPaneHostChange,
}: UseDocumentEditorPluginsArgs) {
  const { activeWorkspaceId, user } = useAuthContext()
  const documentEditorUser = useMemo<DocumentEditorUserApi | null>(() => {
    if (!user) return resolveAnonymousDocumentEditorUser()
    return {
      id: user.id,
      name: user.name,
    }
  }, [user])
  const [panes, setPanes] = useState<RegisteredDocumentEditorPane[]>([])
  const [activePaneKey, setActivePaneKey] = useState<string | null>(null)
  const activeListenersRef = useRef<Map<string, Set<ActiveListener>>>(new Map())

  useEffect(() => {
    for (const [key, listeners] of activeListenersRef.current.entries()) {
      const active = key === activePaneKey
      for (const listener of listeners) {
        try {
          listener(active)
        } catch {
          /* noop */
        }
      }
    }
  }, [activePaneKey])

  const openPane = useCallback((key: string) => {
    setActivePaneKey(key)
  }, [])

  const closePane = useCallback((key?: string | null) => {
    setActivePaneKey((current) => {
      if (!key || current === key) return null
      return current
    })
  }, [])

  useEffect(() => {
    if (!enabled || !document || !editor) {
      setPanes([])
      setActivePaneKey(null)
      return
    }

    let cancelled = false
    const activationDisposers: Array<() => void> = []
    const registeredKeys = new Set<string>()

    const removePane = (key: string) => {
      registeredKeys.delete(key)
      activeListenersRef.current.delete(key)
      setPanes((current) => current.filter((pane) => pane.key !== key))
      setActivePaneKey((current) => {
        if (current !== key) return current
        return null
      })
    }

    const buildContext = (match: DocumentEditorPluginMatch): DocumentEditorActivationContext => {
      const pluginId = String(match.manifest.id)
      const pluginVersion = String(match.manifest.version ?? '')
      const plugin = {
        id: pluginId,
        version: pluginVersion,
        manifest: match.manifest,
      }
      const scopedEditor = createScopedDocumentEditorApi(editor, pluginId)

      const registerPane = (contribution: DocumentEditorPaneContribution) => {
        const localPaneId = String(contribution?.id ?? '').trim()
        if (!localPaneId) {
          throw new Error('document pane id is required')
        }
        if (cancelled) return createInactivePaneRegistration()
        const key = `${pluginId}:${localPaneId}`
        const pane: RegisteredDocumentEditorPane = {
          key,
          pluginId,
          pluginVersion,
          pluginManifest: match.manifest,
          id: localPaneId,
          title: contribution.title || localPaneId,
          order: Number.isFinite(contribution.order) ? Number(contribution.order) : 1000,
          icon: contribution.icon,
          badge: null,
          contribution,
        }

        registeredKeys.add(key)
        setPanes((current) => {
          const next = current.filter((item) => item.key !== key)
          next.push(pane)
          next.sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))
          return next
        })

        return {
          dispose: () => removePane(key),
          setBadge: (value: string | number | null) => {
            if (cancelled) return
            setPanes((current) =>
              current.map((item) => (item.key === key ? { ...item, badge: value } : item)),
            )
          },
          setTitle: (title: string) => {
            if (cancelled) return
            const nextTitle = String(title || localPaneId)
            setPanes((current) =>
              current.map((item) => (item.key === key ? { ...item, title: nextTitle } : item)),
            )
          },
          open: () => {
            if (cancelled) return
            setActivePaneKey(key)
          },
        }
      }

      return {
        plugin,
        user: documentEditorUser,
        document,
        editor: scopedEditor,
        documentPanes: {
          register: registerPane,
        },
        records: {
          list: async (kind, options) => {
            const response = await listPluginRecords(
              pluginId,
              document.id,
              kind,
              options,
              document.token ?? undefined,
            )
            return Array.isArray(response) ? response : ((response as any)?.items ?? [])
          },
        },
        kv: {
          get: async (key) => {
            const response = await getPluginKv(pluginId, document.id, key, document.token ?? undefined)
            return (response as any)?.value
          },
        },
        actions: {
          exec: async (action, payload = {}) => {
            const response = await execPluginAction(
              pluginId,
              action,
              { ...payload, docId: document.id },
              document.token ?? undefined,
            )
            applyDocumentEditorActionEffects((response as any)?.effects)
            if ((response as any)?.ok === false) {
              const message = String((response as any)?.error?.message || (response as any)?.error?.code || 'Plugin action failed')
              throw new Error(message)
            }
            return (response as any)?.data ?? response
          },
        },
        toast: (level, message) => {
          const fn = (sonnerToast as any)[level]
          if (typeof fn === 'function') fn(message)
          else sonnerToast(message)
        },
      }
    }

    ;(async () => {
      try {
        const matches = await resolveDocumentEditorPlugins({
          docId: document.id,
          token: document.token ?? null,
          workspaceId: activeWorkspaceId ?? null,
          document: {
            type: document.type ?? 'markdown',
            title: document.title ?? null,
            readOnly: document.readOnly,
          },
        })
        if (cancelled) return

        for (const match of matches) {
          if (cancelled) break
          try {
            const dispose = await Promise.resolve(
              match.module.activateDocumentEditor(buildContext(match)),
            )
            if (typeof dispose === 'function') {
              if (cancelled) {
                try {
                  dispose()
                } catch {
                  /* noop */
                }
              } else {
                activationDisposers.push(dispose)
              }
            }
          } catch (error) {
            console.error('[plugins] failed to activate document editor plugin', match.manifest?.id, error)
          }
        }
      } catch (error) {
        console.error('[plugins] failed to resolve document editor plugins', error)
      }
    })()

    return () => {
      cancelled = true
      for (const dispose of activationDisposers.splice(0).reverse()) {
        try {
          dispose()
        } catch {
          /* noop */
        }
      }
      for (const key of Array.from(registeredKeys)) {
        removePane(key)
      }
    }
  }, [activeWorkspaceId, document, documentEditorUser, editor, enabled])

  const extraRight = useMemo(() => {
    if (!panes.length || !activePaneKey || !document || !editor) return null
    return (
      <DocumentEditorPanes
        panes={panes}
        activePaneKey={activePaneKey}
        document={document}
        editor={editor}
        user={documentEditorUser}
        onOpenPane={openPane}
        onClosePane={closePane}
        activeListenersRef={activeListenersRef}
      />
    )
  }, [activePaneKey, closePane, document, documentEditorUser, editor, openPane, panes])

  const paneHost = useMemo<DocumentEditorPaneHostState | null>(() => {
    if (!document || !editor) return null
    return {
      panes,
      activePaneKey,
      document,
      editor,
      user: documentEditorUser,
      openPane,
      closePane,
      activeListenersRef,
    }
  }, [activePaneKey, closePane, document, documentEditorUser, editor, openPane, panes])

  useEffect(() => {
    onPaneHostChange?.(enabled ? paneHost : null)
  }, [enabled, onPaneHostChange, paneHost])

  useEffect(() => {
    return () => {
      onPaneHostChange?.(null)
    }
  }, [onPaneHostChange])

  return {
    panes,
    activePaneKey,
    extraRight,
    paneHost,
  }
}

export function DocumentEditorPanes({
  panes,
  activePaneKey,
  document,
  editor,
  user,
  onOpenPane,
  onClosePane,
  activeListenersRef,
}: {
  panes: RegisteredDocumentEditorPane[]
  activePaneKey: string | null
  document: DocumentEditorDocumentApi
  editor: DocumentEditorApi
  user: DocumentEditorUserApi | null
  onOpenPane: (key: string) => void
  onClosePane: (key?: string | null) => void
  activeListenersRef: MutableRefObject<Map<string, Set<ActiveListener>>>
}) {
  const activePane = panes.find((pane) => pane.key === activePaneKey) ?? null
  const handleActivePaneClose = useCallback(() => {
    if (activePaneKey) onClosePane(activePaneKey)
  }, [activePaneKey, onClosePane])

  if (!activePane) return null

  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      <div className="flex min-h-11 items-center justify-between gap-2 border-b px-3">
        <div className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto">
          {panes.map((pane) => (
            <button
              key={pane.key}
              type="button"
              className={cn(
                'inline-flex h-8 max-w-40 shrink-0 items-center gap-1.5 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground',
                pane.key === activePane.key && 'bg-muted text-foreground',
              )}
              onClick={() => onOpenPane(pane.key)}
              title={pane.title}
            >
              {pane.icon ? (
                <span className="shrink-0 text-muted-foreground">
                  {renderDocumentPaneIcon(pane.icon, 'h-3.5 w-3.5')}
                </span>
              ) : null}
              <span className="truncate">{pane.title}</span>
              {pane.badge != null && pane.badge !== '' ? (
                <span className="rounded-full bg-primary px-1.5 py-0.5 text-[10px] font-semibold leading-none text-primary-foreground">
                  {pane.badge}
                </span>
              ) : null}
            </button>
          ))}
        </div>
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className="h-8 w-8 shrink-0"
          onClick={() => onClosePane(activePane.key)}
          aria-label="Close document pane"
          title="Close pane"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="h-full min-h-0">
          <DocumentEditorPaneBody
            key={activePane.key}
            pane={activePane}
            document={document}
            editor={editor}
            user={user}
            activeListenersRef={activeListenersRef}
            onClose={handleActivePaneClose}
          />
        </div>
      </ScrollArea>
    </div>
  )
}

function DocumentEditorPaneBody({
  pane,
  document,
  editor,
  user,
  activeListenersRef,
  onClose,
}: {
  pane: RegisteredDocumentEditorPane
  document: DocumentEditorDocumentApi
  editor: DocumentEditorApi
  user: DocumentEditorUserApi | null
  activeListenersRef: MutableRefObject<Map<string, Set<ActiveListener>>>
  onClose: () => void
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const {
    contribution,
    id: paneId,
    key: paneKey,
    pluginId,
    pluginManifest,
    pluginVersion,
  } = pane
  const scopedEditor = useMemo(
    () => createScopedDocumentEditorApi(editor, pluginId),
    [editor, pluginId],
  )

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    container.innerHTML = ''

    const paneCtx: DocumentEditorPaneRenderContext = {
      plugin: {
        id: pluginId,
        version: pluginVersion,
        manifest: pluginManifest,
      },
      user,
      document,
      editor: scopedEditor,
      pane: {
        id: paneId,
        active: true,
        close: onClose,
        onActiveChange: (callback) => {
          let listeners = activeListenersRef.current.get(paneKey)
          if (!listeners) {
            listeners = new Set()
            activeListenersRef.current.set(paneKey, listeners)
          }
          listeners.add(callback)
          try {
            callback(true)
          } catch {
            /* noop */
          }
          return () => {
            listeners?.delete(callback)
          }
        },
      },
    }

    let dispose: void | (() => void)
    try {
      dispose = contribution.render(container, paneCtx)
    } catch (error) {
      console.error('[plugins] failed to render document pane', pluginId, paneId, error)
      container.textContent = 'Failed to render plugin pane.'
    }

    return () => {
      try {
        if (typeof dispose === 'function') dispose()
      } catch {
        /* noop */
      }
      container.innerHTML = ''
    }
  }, [
    activeListenersRef,
    contribution,
    document,
    onClose,
    paneId,
    paneKey,
    pluginId,
    pluginManifest,
    pluginVersion,
    scopedEditor,
    user,
  ])

  return <div ref={containerRef} className="h-full min-h-0" />
}
