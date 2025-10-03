import { Columns, Download, Eye, FileCode, Link2, Menu, Moon, Search, Share2, Sun } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState, type ReactElement } from 'react'
import { toast } from 'sonner'

import { useTheme } from '@/shared/contexts/theme-context'
import { cn } from '@/shared/lib/utils'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { SidebarTrigger } from '@/shared/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { downloadDocumentArchive } from '@/entities/document'

import { useAuthContext } from '@/features/auth'
import { useEditorContext, useViewController } from '@/features/edit-document'
import { ShareDialog } from '@/features/sharing'

import { DocumentPresence } from '@/widgets/header/components/DocumentPresence'
import { MobileHeaderMenu } from '@/widgets/header/components/MobileHeaderMenu'
import SearchDialog from '@/widgets/header/SearchDialog'

import type { DocumentHeaderAction } from '@/processes/collaboration/contexts/realtime-context'

// Using ViewContext instead of window events

export type HeaderRealtimeState = {
  connected: boolean
  showEditorFeatures: boolean
  documentTitle?: string
  documentId?: string
  documentPath?: string
  documentStatus?: string
  documentBadge?: string
  documentActions?: DocumentHeaderAction[]
  onlineUsers: Array<{ id: string; name: string; color?: string; clientId?: number }>
}

interface HeaderProps {
  className?: string
  realtime?: HeaderRealtimeState
  variant?: 'overlay' | 'mobile'
}

const defaultRealtimeState: HeaderRealtimeState = {
  connected: false,
  showEditorFeatures: false,
  documentTitle: undefined,
  documentId: undefined,
  documentPath: undefined,
  documentStatus: undefined,
  documentBadge: undefined,
  documentActions: [],
  onlineUsers: [],
}

export function Header({ className, realtime, variant = 'overlay' }: HeaderProps) {
  const { isDarkMode, toggleTheme } = useTheme()
  const { signOut } = useAuthContext()
  const rt = realtime ?? defaultRealtimeState
  const vc = useViewController()
  const { editor } = useEditorContext()
  const [mounted, setMounted] = useState(false)
  const [searchOpenLocal, setSearchOpenLocal] = useState(false)
  const [searchPresetTag, setSearchPresetTag] = useState<string | null>(null)
  const [shareOpen, setShareOpen] = useState(false)
  const [headerViewMode, setHeaderViewMode] = useState<'editor' | 'split' | 'preview'>('split')
  const [isCompact, setIsCompact] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const documentBadge = rt.documentBadge
  const documentStatus = rt.documentStatus
  const documentActions = rt.documentActions ?? []
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
  const canDownload = Boolean(rt.documentId)
  const iconClass = 'h-[18px] w-[18px]'

  useEffect(() => { setMounted(true) }, [])
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); setSearchOpenLocal(true) }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])
  useEffect(() => { setHeaderViewMode(vc.viewMode) }, [vc.viewMode])
  useEffect(() => {
    setSearchPresetTag(vc.searchPresetTag)
    if (vc.searchNonce > 0) setSearchOpenLocal(true)
  }, [vc.searchNonce, vc.searchPresetTag])
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
  useEffect(() => {
    if (!mounted) return
    if (isCompact && vc.viewMode === 'split') {
      vc.setViewMode('preview')
    }
  }, [isCompact, vc, vc.viewMode, mounted])
  // Dropped save-status pill and compatibility props

  const effectiveViewMode = headerViewMode
  const changeView = useCallback((mode: 'editor' | 'split' | 'preview') => {
    if (mode === 'split' && isCompact) {
      vc.setViewMode('preview')
      return
    }
    vc.setViewMode(mode)
  }, [isCompact, vc])
  const shareHandler = () => {
    if (!rt.documentId) return
    setShareOpen(true)
  }
  const handleDownload = useCallback(async () => {
    if (!rt.documentId || downloading) return
    setDownloading(true)
    try {
      const filename = await downloadDocumentArchive(rt.documentId, { title: rt.documentTitle })
      toast.success(`Download ready: ${filename}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to download document'
      toast.error(message)
    } finally {
      setDownloading(false)
    }
  }, [rt.documentId, rt.documentTitle, downloading])
  const handleSignOut = useCallback(() => {
    void signOut()
  }, [signOut])
  const handleBacklinksClick = useCallback(() => {
    if (!isCompact) {
      changeView('split')
    }
    vc.toggleBacklinks()
  }, [vc, changeView, isCompact])

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

  const viewModeButtons = useMemo(() => {
    const items: Array<{ mode: 'editor' | 'split' | 'preview'; icon: ReactElement; tooltip: string }> = [
      { mode: 'editor', icon: <FileCode className={iconClass} />, tooltip: 'Editor only' },
    ]
    if (!isCompact) {
      items.push({ mode: 'split', icon: <Columns className={iconClass} />, tooltip: 'Split view' })
    }
    items.push({ mode: 'preview', icon: <Eye className={iconClass} />, tooltip: 'Preview only' })
    return items
  }, [isCompact])

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
          {documentActions.length > 0 && (
            <div className="flex items-center gap-1">
              {documentActions.map((action) => (
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
          {rt.showEditorFeatures && (
            <div className="flex items-center gap-1 rounded-full border border-border/60 bg-background/80 px-1 py-0.5">
              {viewModeButtons.map((item, idx) => {
                const first = idx === 0
                const last = idx === viewModeButtons.length - 1
                const isActive = effectiveViewMode === item.mode
                return (
                  <Tooltip key={item.mode}>
                    <TooltipTrigger asChild>
                      <span>
                        <Button
                          onClick={() => changeView(item.mode)}
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
              {rt.documentId && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span>
                      <Button
                        onClick={handleBacklinksClick}
                        variant="ghost"
                        className={cn(
                          'h-8 w-8 rounded-full transition-colors hover:bg-muted/70',
                          (vc.showBacklinks || false) && 'bg-accent text-accent-foreground',
                        )}
                      >
                        <Link2 className={iconClass} />
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>Toggle backlinks</TooltipContent>
                </Tooltip>
              )}
            </div>
          )}

          {canDownload && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span>
                  <Button
                    onClick={handleDownload}
                    variant="ghost"
                    className="h-8 w-8 rounded-full transition-colors hover:bg-muted/70"
                    disabled={downloading}
                  >
                    <Download className={iconClass} />
                  </Button>
                </span>
              </TooltipTrigger>
              <TooltipContent>{downloading ? 'Preparing…' : 'Download'}</TooltipContent>
            </Tooltip>
          )}

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
              <Button onClick={() => setSearchOpenLocal(true)} variant="ghost" className="grid h-9 w-9 place-items-center rounded-xl border border-border/50 bg-muted/20 text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground">
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
        showEditorFeatures={rt.showEditorFeatures}
        headerViewMode={headerViewMode}
        changeView={changeView}
        isCompact={isCompact}
        canShare={canShare}
        canDownload={canDownload}
        onShare={shareHandler}
        onDownload={handleDownload}
        downloading={downloading}
        onToggleTheme={() => { toggleTheme(); setMobileMenuOpen(false) }}
        onSignOut={() => { handleSignOut(); setMobileMenuOpen(false) }}
        documentActions={documentActions}
      />
      {rt.documentId && (
        <ShareDialog open={shareOpen} onOpenChange={setShareOpen} targetId={rt.documentId} />
      )}
      <SearchDialog open={searchOpenLocal} onOpenChange={setSearchOpenLocal} presetTag={searchPresetTag} />
    </>
  )
}

export default Header
