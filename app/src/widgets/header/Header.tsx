import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { Columns, Eye, FileCode, Link2, Menu, Moon, Search, Share2, Sun } from 'lucide-react'
import { memo, useCallback, useEffect, useMemo, useRef, useState, type ReactElement } from 'react'
import { toast } from 'sonner'

import { useTheme } from '@/shared/contexts/theme-context'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { useShortcut } from '@/shared/hooks/use-shortcut'
import { MOSAIC_CURRENT_VIEW_MODE_EVENT, dispatchMosaicSetViewMode, dispatchOpenBacklinksTile } from '@/shared/lib/mosaic-events'
import { cn } from '@/shared/lib/utils'
import type { DocumentHeaderAction } from '@/shared/types/document'
import type { HeaderRealtimeState } from '@/shared/types/header'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { SidebarTrigger, useSidebar } from '@/shared/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { createDocument, documentKeys, fetchDocumentMeta } from '@/entities/document'

import { useAuthContext } from '@/features/auth'
import { useEditorContext, useViewController } from '@/features/edit-document'
import { DocumentPresence } from '@/features/header/ui/DocumentPresence'
import { MobileHeaderMenu } from '@/features/header/ui/MobileHeaderMenu'
import SearchDialog from '@/features/search/ui/SearchDialog'
import { ShareDialog } from '@/features/sharing'
import { createTemporaryDocumentEntry } from '@/features/temporary-document'

// Using ViewContext instead of window events

interface HeaderProps {
  className?: string
  realtime?: HeaderRealtimeState
  variant?: 'overlay' | 'mobile'
}

const PLUGIN_USES_SPLIT_EDITOR_EVENT = 'refmd:plugin:uses-split-editor'

const defaultRealtimeState: HeaderRealtimeState = {
  connected: false,
  showEditorFeatures: false,
  documentTitle: undefined,
  documentId: undefined,
  documentPath: undefined,
  documentPluginId: undefined,
  documentStatus: undefined,
  documentBadge: undefined,
  documentActions: [],
  onlineUsers: [],
}

type ViewMode = 'editor' | 'split' | 'preview'
type ViewModeButtonItem = { mode: ViewMode; icon: ReactElement; tooltip: string }

const HeaderViewModeControls = memo(function HeaderViewModeControls({
  buttons,
  activeMode,
  onChange,
  showBacklinksButton,
  onBacklinksClick,
  iconClass,
}: {
  buttons: ViewModeButtonItem[]
  activeMode: ViewMode
  onChange: (mode: ViewMode) => void
  showBacklinksButton: boolean
  onBacklinksClick: () => void
  iconClass: string
}) {
  return (
    <div className="flex items-center gap-1 rounded-full border border-border/60 bg-background/80 px-1 py-0.5">
      {buttons.map((item, idx) => {
        const first = idx === 0
        const last = idx === buttons.length - 1
        const isActive = activeMode === item.mode
        return (
          <Tooltip key={item.mode}>
            <TooltipTrigger asChild>
              <span>
                <Button
                  onClick={() => onChange(item.mode)}
                  variant="ghost"
                  className={cn(
                    'h-8 rounded-full px-2 text-sm transition-colors',
                    first && 'pl-3',
                    last && 'pr-3',
                    isActive ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted/70',
                  )}
                >
                  {item.icon}
                </Button>
              </span>
            </TooltipTrigger>
            <TooltipContent>{item.tooltip}</TooltipContent>
          </Tooltip>
        )
      })}
      {showBacklinksButton && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>
              <Button
                onClick={onBacklinksClick}
                variant="ghost"
                className={cn('h-8 w-8 rounded-full transition-colors hover:bg-muted/70')}
              >
                <Link2 className={iconClass} />
              </Button>
            </span>
          </TooltipTrigger>
          <TooltipContent>Open backlinks tile</TooltipContent>
        </Tooltip>
      )}
    </div>
  )
})

export function Header({ className, realtime, variant = 'overlay' }: HeaderProps) {
  const { isDarkMode, toggleTheme } = useTheme()
  const { signOut } = useAuthContext()
  const queryClient = useQueryClient()
  const rt = realtime ?? defaultRealtimeState
  const isMobile = useIsMobile()
  const vc = useViewController()
  const { editor } = useEditorContext()
  const { toggleSidebar } = useSidebar()
  const navigate = useNavigate()
  const focusedDocumentIdRef = useRef<string | undefined>(undefined)
  const mosaicViewModeRef = useRef<Map<string, ViewMode>>(new Map())
  const [mounted, setMounted] = useState(false)
  const [isCompact, setIsCompact] = useState(false)
  const [headerViewMode, setHeaderViewMode] = useState<'editor' | 'split' | 'preview'>(() => {
    const initial = vc.viewMode
    return initial === 'editor' || initial === 'split' || initial === 'preview' ? initial : 'split'
  })
  const [searchOpenLocal, setSearchOpenLocal] = useState(false)
  const [searchPresetTag, setSearchPresetTag] = useState<string | null>(null)
  const [shareOpen, setShareOpen] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const documentBadge = rt.documentBadge
  const documentStatus = rt.documentStatus
  const documentActions = rt.documentActions ?? []
  const textActions = documentActions.filter((action) => !action.icon)
  const iconActions = documentActions.filter((action) => action.icon)
  const handleDocumentActionClick = useCallback((action: DocumentHeaderAction) => {
    try {
      action.onSelect?.()
    } catch (error) {
      console.error('[header] document action handler failed', error)
    }
  }, [])

  const resolveActionVariant = useCallback((variant?: DocumentHeaderAction['variant']) => {
    switch (variant) {
      case 'primary':
        return 'default' as const
      case 'outline':
        return 'outline' as const
      default:
        return 'secondary' as const
    }
  }, [])
  
  const canShare = Boolean(rt.documentId)
  focusedDocumentIdRef.current = rt.documentId
  const iconClass = 'h-[18px] w-[18px]'

  useEffect(() => { setMounted(true) }, [])
  useEffect(() => {
    if (rt.documentId) return
    const mode = vc.viewMode
    if (mode === 'editor' || mode === 'split' || mode === 'preview') {
      setHeaderViewMode(mode)
    }
  }, [rt.documentId, vc.viewMode])

  useEffect(() => {
    if (!rt.documentId) return
    const mode = mosaicViewModeRef.current.get(rt.documentId)
    if (!mode) return
    setHeaderViewMode(mode)
  }, [rt.documentId])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ documentId?: string; mode?: string }>).detail
      const documentId = typeof detail?.documentId === 'string' ? detail.documentId.trim() : ''
      const mode = detail?.mode
      if (!documentId) return
      if (mode !== 'editor' && mode !== 'split' && mode !== 'preview') return
      mosaicViewModeRef.current.set(documentId, mode)
      if (focusedDocumentIdRef.current !== documentId) return
      setHeaderViewMode(mode)
    }
    window.addEventListener(MOSAIC_CURRENT_VIEW_MODE_EVENT, handler as EventListener)
    return () => window.removeEventListener(MOSAIC_CURRENT_VIEW_MODE_EVENT, handler as EventListener)
  }, [])
  useEffect(() => {
    if (typeof window === 'undefined') return
    const mq = window.matchMedia('(max-width: 1024px)')
    const update = (event?: MediaQueryListEvent) => {
      setIsCompact(event ? event.matches : mq.matches)
    }
    update()
    mq.addEventListener('change', update)
    return () => mq.removeEventListener('change', update)
  }, [])
  useShortcut(
    'global.search.open',
    useCallback(
      (event) => {
        const target = event.target as HTMLElement | null
        if (target) {
          const tagName = target.tagName
          const isInputElement = tagName === 'INPUT' || tagName === 'TEXTAREA' || target.isContentEditable
          const insideEditor = Boolean(target.closest('.cm-editor'))
          if (isInputElement && !insideEditor) {
            return
          }
        }
        setSearchOpenLocal(true)
      },
      [setSearchOpenLocal],
    ),
  )
  useShortcut(
    'global.settings.open',
    useCallback(() => {
      navigate({ to: '/settings' })
    }, [navigate]),
  )
  useShortcut(
    'global.profile.open',
    useCallback(() => {
      navigate({ to: '/profile' })
    }, [navigate]),
  )
  useShortcut(
    'global.plugins.open',
    useCallback(() => {
      navigate({ to: '/settings/plugins' })
    }, [navigate]),
  )
  const creatingDocumentRef = useRef(false)

  useShortcut(
    'global.document.new',
    useCallback(() => {
      if (creatingDocumentRef.current) return
      creatingDocumentRef.current = true
      ;(async () => {
        try {
          const doc = await createDocument({ parent_id: null })
          await queryClient.invalidateQueries({ queryKey: documentKeys.all })
          toast.success('Document created')
          navigate({ to: '/document/$id', params: { id: doc.id } })
        } catch (error) {
          console.error('[header] failed to create document from shortcut', error)
          const message = error instanceof Error ? error.message : 'Failed to create document'
          toast.error(message)
        } finally {
          creatingDocumentRef.current = false
        }
      })()
    }, [navigate, queryClient]),
  )

  useShortcut(
    'global.temporary.open',
    useCallback(() => {
      if (typeof window === 'undefined') return
      const entry = createTemporaryDocumentEntry()
      navigate({ to: '/temporary/$id', params: { id: entry.id } })
    }, [navigate]),
  )
  useShortcut(
    'global.theme.toggle',
    useCallback(() => {
      toggleTheme()
    }, [toggleTheme]),
  )
  useShortcut(
    'global.sidebar.toggle',
    useCallback(() => {
      toggleSidebar()
    }, [toggleSidebar]),
  )
  useEffect(() => {
    setSearchPresetTag(vc.searchPresetTag)
    if (vc.searchNonce > 0) setSearchOpenLocal(true)
  }, [vc.searchNonce, vc.searchPresetTag])
  // Dropped save-status pill and compatibility props

  const effectiveViewMode = headerViewMode
  const [splitCapablePluginDocs, setSplitCapablePluginDocs] = useState<Set<string>>(() => new Set())
  useEffect(() => {
    if (typeof window === 'undefined') return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ docId?: string }>).detail
      const docId = typeof detail?.docId === 'string' ? detail.docId.trim() : ''
      if (!docId) return
      setSplitCapablePluginDocs((prev) => {
        if (prev.has(docId)) return prev
        const next = new Set(prev)
        next.add(docId)
        return next
      })
    }
    window.addEventListener(PLUGIN_USES_SPLIT_EDITOR_EVENT, handler as EventListener)
    return () => window.removeEventListener(PLUGIN_USES_SPLIT_EDITOR_EVENT, handler as EventListener)
  }, [])

  const pluginDocMetaQuery = useQuery({
    queryKey: ['document-meta', rt.documentId ?? null, 'header'],
    queryFn: async () => {
      const docId = typeof rt.documentId === 'string' ? rt.documentId.trim() : ''
      if (!docId) return null as any
      const token = (() => {
        if (typeof window === 'undefined') return undefined
        try {
          const params = new URLSearchParams(window.location.search)
          const raw = params.get('token')
          return raw && raw.trim().length > 0 ? raw.trim() : undefined
        } catch {
          return undefined
        }
      })()
      return fetchDocumentMeta(docId, token)
    },
    staleTime: 60_000,
    enabled: Boolean(rt.documentId),
  })
  const pluginIdFromMeta = useMemo(() => {
    const raw = (pluginDocMetaQuery.data as any)?.created_by_plugin
    return typeof raw === 'string' && raw.trim() ? raw.trim() : ''
  }, [pluginDocMetaQuery.data])
  const pluginIdHint = typeof rt.documentPluginId === 'string' ? rt.documentPluginId.trim() : ''
  const isPluginDocument = Boolean(pluginIdFromMeta || pluginIdHint)
  const pluginViewPolicy = useMemo<'normal' | 'splitCapable' | 'previewOnly'>(() => {
    if (!rt.documentId) return 'normal'
    if (!isPluginDocument) return 'normal'
    return splitCapablePluginDocs.has(rt.documentId) ? 'splitCapable' : 'previewOnly'
  }, [isPluginDocument, rt.documentId, splitCapablePluginDocs])
  const disallowSplit = pluginViewPolicy === 'previewOnly'
  const changeView = useCallback(
    (mode: ViewMode) => {
      const normalized = pluginViewPolicy === 'previewOnly' ? 'preview' : mode
      const nextMode = normalized === 'split' && isCompact ? 'preview' : normalized
      setHeaderViewMode(nextMode)
      if (isMobile) {
        vc.setViewMode(nextMode)
        return
      }
      const focusedDocumentId = focusedDocumentIdRef.current
      if (focusedDocumentId) {
        dispatchMosaicSetViewMode(focusedDocumentId, nextMode)
      }
      vc.setViewMode(nextMode)
    },
    [isCompact, isMobile, pluginViewPolicy, vc],
  )

  useEffect(() => {
    if (!mounted) return
    if (pluginViewPolicy !== 'previewOnly') return
    setHeaderViewMode('preview')
    const focusedDocumentId = rt.documentId
    if (focusedDocumentId) {
      dispatchMosaicSetViewMode(focusedDocumentId, 'preview')
    }
    if (isMobile) {
      vc.setViewMode('preview')
    }
  }, [isMobile, mounted, pluginViewPolicy, rt.documentId, vc])

  const shareHandler = () => {
    if (!rt.documentId) return
    setShareOpen(true)
  }
  const handleSignOut = useCallback(() => {
    void signOut()
  }, [signOut])
  const handleBacklinksClick = useCallback(() => {
    const focusedDocumentId = focusedDocumentIdRef.current
    if (!focusedDocumentId) return
    dispatchOpenBacklinksTile(focusedDocumentId)
  }, [])

  useShortcut(
    'view.mode.editor',
    useCallback(() => {
      changeView('editor')
    }, [changeView]),
  )

  useShortcut(
    'view.mode.preview',
    useCallback(() => {
      changeView('preview')
    }, [changeView]),
  )

  useShortcut(
    'view.mode.split',
    useCallback(() => {
      changeView('split')
    }, [changeView]),
  )

  useShortcut(
    'view.backlinks.toggle',
    useCallback(() => {
      handleBacklinksClick()
    }, [handleBacklinksClick]),
  )

  useEffect(() => {
    if (!rt.documentId && shareOpen) {
      setShareOpen(false)
    }
  }, [rt.documentId, shareOpen])

  const handleCollaboratorSelect = useCallback(
    (clientId?: number) => {
      if (!clientId) return
      const instance = editor as {
        getDomNode?: () => HTMLElement | null
        getScrollTop?: () => number
        setScrollTop?: (top: number) => void
      } | null
      const root = instance?.getDomNode?.()
      if (!root) return
      const head = root.querySelector(`.yRemoteSelectionHead-${clientId}`) as HTMLElement | null
      const selection = head ?? (root.querySelector(`.yRemoteSelection-${clientId}`) as HTMLElement | null)
      if (!selection) return

      const editorRect = root.getBoundingClientRect()
      const selectionRect = selection.getBoundingClientRect()
      const current = instance?.getScrollTop?.() ?? 0
      const delta = selectionRect.top - (editorRect.top + editorRect.height / 2)
      instance?.setScrollTop?.(current + delta)
    },
    [editor],
  )

  useEffect(() => {
    if (!mounted) return
    if (isCompact && headerViewMode === 'split') {
      setHeaderViewMode('preview')
    }
  }, [headerViewMode, isCompact, mounted])

  useEffect(() => {
    if (!isMobile) return
    const next = vc.viewMode === 'split' ? 'preview' : vc.viewMode
    if (next === headerViewMode) return
    setHeaderViewMode(next)
  }, [headerViewMode, isMobile, vc.viewMode])

  const viewModeButtons = useMemo(() => {
    if (pluginViewPolicy === 'previewOnly') {
      return [{ mode: 'preview', icon: <Eye className={iconClass} />, tooltip: 'Preview only' }] satisfies ViewModeButtonItem[]
    }
    const order: ViewMode[] = disallowSplit || isCompact ? ['editor', 'preview'] : ['editor', 'split', 'preview']
    return order.map((mode) => {
      if (mode === 'editor') return { mode, icon: <FileCode className={iconClass} />, tooltip: 'Editor only' }
      if (mode === 'split') return { mode, icon: <Columns className={iconClass} />, tooltip: 'Split view' }
      return { mode, icon: <Eye className={iconClass} />, tooltip: 'Preview only' }
    })
  }, [disallowSplit, iconClass, isCompact, pluginViewPolicy])

  const desktopToolbar = (
    <div className="pointer-events-none absolute inset-x-0 top-5 z-30 flex justify-center px-4 sm:px-5 md:px-6">
      <div className="pointer-events-auto flex w-full max-w-6xl flex-col gap-3 rounded-3xl border border-border/60 bg-background/95 px-4 py-4 shadow-sm backdrop-blur supports-[backdrop-filter]:bg-background/70 md:flex-row md:items-center md:gap-4 md:rounded-full md:py-2">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <SidebarTrigger className="h-9 w-9 rounded-xl border border-border/50 bg-muted/20 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground" />
          <div className="min-w-0 flex flex-col gap-1 justify-center">
            <div className="flex min-w-0 items-center gap-3">
              {rt.documentTitle ? (
                <p className="truncate text-base font-semibold leading-tight text-foreground">{rt.documentTitle}</p>
              ) : (
                <p className="text-base font-medium text-muted-foreground">Collaborative Markdown Editor</p>
              )}
              <div className="hidden lg:flex items-center gap-2 text-xs text-muted-foreground/80">
                <DocumentPresence realtime={rt} onCollaboratorSelect={handleCollaboratorSelect} showTitle={false} />
              </div>
              {documentBadge && (
                <Badge variant="outline" className="hidden md:inline-flex items-center gap-1 rounded-full border-border/60 bg-muted/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.25em] text-muted-foreground">
                  {documentBadge}
                </Badge>
              )}
            </div>
            {rt.documentPath && (
              <p className="truncate text-xs text-muted-foreground/70">{rt.documentPath}</p>
            )}
            {documentStatus && (
              <p className="truncate text-xs text-muted-foreground/65">{documentStatus}</p>
            )}
          </div>
        </div>

        <div className="flex w-full flex-1 justify-center">
          <Button
            onClick={() => setSearchOpenLocal(true)}
            variant="outline"
            className="group flex h-10 w-full max-w-xl items-center gap-3 rounded-2xl border border-border/70 bg-background/90 px-4 text-sm text-muted-foreground transition-colors hover:border-border hover:text-foreground"
          >
            <Search className="h-4 w-4 text-muted-foreground/70 group-hover:text-foreground" />
            <span className="flex-1 truncate text-left font-medium text-muted-foreground group-hover:text-foreground">
              Search notes and commands
            </span>
            <kbd className="rounded border border-border/60 bg-muted/30 px-2 py-0.5 text-[11px] font-medium text-muted-foreground/80">
              ⌘K
            </kbd>
          </Button>
        </div>

        <div className="flex items-center gap-2">
          {rt.showEditorFeatures && (
            <HeaderViewModeControls
              buttons={viewModeButtons}
              activeMode={effectiveViewMode}
              onChange={changeView}
              showBacklinksButton={Boolean(rt.documentId)}
              onBacklinksClick={handleBacklinksClick}
              iconClass={iconClass}
            />
          )}
          {textActions.length > 0 && (
            <div className="flex items-center gap-1">
              {textActions.map((action) => (
                <Button
                  key={action.id ?? action.label}
                  onClick={() => handleDocumentActionClick(action)}
                  variant={resolveActionVariant(action.variant)}
                  disabled={action.disabled}
                  className="h-9 rounded-full px-3 text-sm"
                >
                  {action.label}
                </Button>
              ))}
            </div>
          )}

          {iconActions.map((action) => (
            <Tooltip key={action.id ?? action.label}>
              <TooltipTrigger asChild>
                <span>
                  <Button
                    onClick={() => handleDocumentActionClick(action)}
                    variant="ghost"
                    className={cn(
                      'h-9 w-9 rounded-full transition-colors hover:bg-muted/70',
                      action.disabled && 'opacity-50',
                    )}
                    disabled={action.disabled}
                    aria-label={action.tooltip ?? action.label}
                  >
                    {action.icon}
                  </Button>
                </span>
              </TooltipTrigger>
              <TooltipContent>{action.tooltip ?? action.label}</TooltipContent>
            </Tooltip>
          ))}
          {canShare && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span>
                  <Button onClick={shareHandler} variant="ghost" className="h-8 w-8 rounded-full transition-colors hover:bg-muted/70">
                    <Share2 className={iconClass} />
                  </Button>
                </span>
              </TooltipTrigger>
              <TooltipContent>Share</TooltipContent>
            </Tooltip>
          )}

          <Tooltip>
            <TooltipTrigger asChild>
              <span>
                <Button onClick={toggleTheme} variant="ghost" className="h-8 w-8 rounded-full transition-colors hover:bg-muted/70">
                  {mounted ? (isDarkMode ? <Sun className={iconClass} /> : <Moon className={iconClass} />) : <Sun className={iconClass} />}
                </Button>
              </span>
            </TooltipTrigger>
            <TooltipContent>{mounted ? (isDarkMode ? 'Light mode' : 'Dark mode') : 'Toggle theme'}</TooltipContent>
          </Tooltip>

        </div>
      </div>
    </div>
  )

  const mobileHeader = (
    <>
      <header className={cn('px-3 sm:px-4 pt-4 text-header-foreground', className)}>
        <div className="rounded-3xl border border-border/60 bg-background/95 px-3 py-3 shadow-sm backdrop-blur supports-[backdrop-filter]:bg-background/80">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="h-9 w-9 rounded-xl border border-border/50 bg-muted/20 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground" />
              <Button
                onClick={() => setSearchOpenLocal(true)}
                variant="ghost"
                className="grid h-9 w-9 place-items-center rounded-xl border border-border/50 bg-muted/20 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground"
              >
                <Search className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex min-w-0 flex-1 flex-col items-center justify-center text-center">
              <div className="flex w-full items-center justify-center gap-2">
                <span className="truncate text-sm font-semibold text-foreground">{rt.documentTitle || 'RefMD'}</span>
                <div className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground/80">
                  <DocumentPresence realtime={rt} onCollaboratorSelect={handleCollaboratorSelect} showTitle={false} />
                </div>
                {documentBadge && (
                  <Badge variant="outline" className="hidden sm:inline-flex items-center gap-1 rounded-full border-border/60 bg-muted/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.25em] text-muted-foreground">
                    {documentBadge}
                  </Badge>
                )}
              </div>
              {rt.documentPath && (
                <span className="truncate text-[11px] text-muted-foreground/70">{rt.documentPath}</span>
              )}
              {documentStatus && (
                <span className="truncate text-[11px] text-muted-foreground/65">{documentStatus}</span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {canShare && (
                <Button onClick={shareHandler} variant="ghost" className="h-9 w-9 rounded-full border border-border/50 bg-muted/20 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground">
                  <Share2 className="h-4 w-4" />
                </Button>
              )}
              <Button
                onClick={() => setMobileMenuOpen(true)}
                variant="ghost"
                className="grid h-9 w-9 place-items-center rounded-xl border border-border/50 bg-muted/20 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground md:hidden"
                aria-label="Open menu"
              >
                <Menu className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </header>
    </>
  )

  return (
    <>
      {variant === 'overlay' ? desktopToolbar : mobileHeader}
      <MobileHeaderMenu
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        canShare={canShare}
        onShare={shareHandler}
        onToggleTheme={() => { toggleTheme(); setMobileMenuOpen(false) }}
        onSignOut={() => { handleSignOut(); setMobileMenuOpen(false) }}
        documentActions={documentActions}
        viewMode={
          rt.showEditorFeatures && pluginViewPolicy !== 'previewOnly'
            ? (effectiveViewMode === 'editor' ? 'editor' : 'preview')
            : undefined
        }
        onChangeViewMode={rt.showEditorFeatures && pluginViewPolicy !== 'previewOnly' ? (mode) => changeView(mode) : undefined}
      />
      {rt.documentId && (
        <ShareDialog open={shareOpen} onOpenChange={setShareOpen} targetId={rt.documentId} />
      )}
      <SearchDialog open={searchOpenLocal} onOpenChange={setSearchOpenLocal} presetTag={searchPresetTag} />
    </>
  )
}

export type { HeaderRealtimeState } from '@/shared/types/header'

export default Header
