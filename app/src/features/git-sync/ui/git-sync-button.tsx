import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertCircle, CheckCircle, Eye, FileX, GitCommit, History, Loader2, Settings } from 'lucide-react'
import { useMemo, useState, useCallback } from 'react'
import { toast } from 'sonner'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { getStatus, getConfig, syncNow, initRepository } from '@/entities/git'

import GitChangesDialog from './git-changes-dialog'
import GitConfigDialog from './git-config-dialog'
import GitHistoryDialog from './git-history-dialog'

type Props = { className?: string; compact?: boolean }

type GitStatus = Awaited<ReturnType<typeof getStatus>>
type GitConfig = Awaited<ReturnType<typeof getConfig>>

function useGitSyncController() {
  const qc = useQueryClient()
  const isMobile = useIsMobile()
  const [showConfig, setShowConfig] = useState(false)
  const [showChanges, setShowChanges] = useState(false)
  const [showHistory, setShowHistory] = useState(false)

  const {
    data: status,
    isLoading: statusLoading,
    error: statusError,
  } = useQuery<GitStatus, unknown>({ queryKey: ['git-status'], queryFn: () => getStatus(), refetchInterval: 10000, retry: false })
  const { data: config } = useQuery<GitConfig>({ queryKey: ['git-config'], queryFn: () => getConfig(), retry: false })

  const syncMutation = useMutation({
    mutationFn: () => syncNow({ requestBody: { message: undefined } }),
    onSuccess: (data: any) => {
      toast.success(`Sync complete: ${(data?.files_changed ?? 0)} files changed`)
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
    onError: (e: any) => {
      toast.error(`Sync failed: ${e?.message || e}`)
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
  })

  const initMutation = useMutation({
    mutationFn: () => initRepository(),
    onSuccess: () => {
      toast.success('Git repository initialized')
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
    onError: (e: any) => toast.error(`Initialization failed: ${e?.message || e}`),
  })

  const syncPending = syncMutation.isPending || initMutation.isPending
  const hasChanges = ((status?.uncommitted_changes || 0) + (status?.untracked_files || 0)) > 0
  const isConfigured = Boolean(config) && Boolean(status?.repository_initialized)

  const handleSync = useCallback(() => {
    if (statusError || !config || !status?.repository_initialized) setShowConfig(true)
    else syncMutation.mutate()
  }, [statusError, config, status, syncMutation])

  const openConfig = useCallback(() => setShowConfig(true), [])
  const openChanges = useCallback(() => {
    if (!status?.repository_initialized) setShowConfig(true)
    else setShowChanges(true)
  }, [status])
  const openHistory = useCallback(() => {
    if (!status?.repository_initialized) setShowConfig(true)
    else setShowHistory(true)
  }, [status])

  const statusText = useMemo(() => {
    if (statusLoading) return 'Loading…'
    if (statusError || !config) return 'Configuration required'
    if (!status?.repository_initialized) return 'Repository not initialized'
    if (hasChanges) return `${(status?.uncommitted_changes || 0) + (status?.untracked_files || 0)} changes`
    if (status?.has_remote && status?.last_sync_status === 'error') return 'Push failed'
    return 'Up to date'
  }, [config, hasChanges, status, statusError, statusLoading])

  const tooltipText = useMemo(() => {
    if (statusError || !config) return 'Git configuration required'
    if (!status?.repository_initialized) return 'Click to configure Git'
    if (hasChanges) return 'Click to sync changes'
    if (status?.has_remote && status?.last_sync_status === 'error') return status?.last_sync_message || 'Last push failed'
    return 'Repository is up to date'
  }, [config, hasChanges, status, statusError])

  const icon = useMemo(() => {
    if (syncPending || statusLoading) return <Loader2 className="h-4 w-4 animate-spin" />
    if (statusError) return <AlertCircle className="h-4 w-4 text-destructive" />
    if (!config || !status?.repository_initialized) return <AlertCircle className="h-4 w-4 text-muted-foreground" />
    if (!hasChanges && status?.has_remote && status?.last_sync_status === 'error') return <AlertCircle className="h-4 w-4 text-destructive" />
    if (hasChanges) return <GitCommit className="h-4 w-4 text-orange-500" />
    return <CheckCircle className="h-4 w-4 text-emerald-500" />
  }, [config, hasChanges, status, statusError, statusLoading, syncPending])

  return {
    isMobile,
    syncPending,
    icon,
    statusText,
    tooltipText,
    handleSync,
    openConfig,
    openChanges,
    openHistory,
    showConfig,
    setShowConfig,
    showChanges,
    setShowChanges,
    showHistory,
    setShowHistory,
    isConfigured,
  }
}

export default function GitSyncButton({ className, compact = false }: Props) {
  const controller = useGitSyncController()
  const {
    isMobile,
    syncPending,
    icon,
    statusText,
    tooltipText,
    handleSync,
    openConfig,
    openChanges,
    openHistory,
    showConfig,
    setShowConfig,
    showChanges,
    setShowChanges,
    showHistory,
    setShowHistory,
    isConfigured,
  } = controller

  const [menuOpen, setMenuOpen] = useState(false)
  const tooltipSide = isMobile ? 'bottom' : 'right'
  const triggerClasses = cn(
    'h-9 w-9 rounded-full border border-border/40 bg-background/70 text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground',
    !compact && 'shadow-sm',
    syncPending && 'pointer-events-none opacity-80',
    className,
  )

  return (
    <>
      <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
        <Tooltip>
          <TooltipTrigger asChild>
            <span>
              <DropdownMenuTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  className={triggerClasses}
                >
                  <span className="flex h-full w-full items-center justify-center">{icon}</span>
                </Button>
              </DropdownMenuTrigger>
            </span>
          </TooltipTrigger>
          <TooltipContent side={tooltipSide}>{tooltipText}</TooltipContent>
        </Tooltip>

        <DropdownMenuContent align="end" className={cn('w-60', overlayMenuClass)}>
            <div className="px-3 py-2">
              <div className="flex items-center gap-3">
                <span className="flex h-9 w-9 items-center justify-center rounded-full bg-background/70">{icon}</span>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-foreground">Git Sync</p>
                  <p className="truncate text-xs text-muted-foreground/80">{statusText}</p>
                </div>
              </div>
          </div>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onClick={() => {
              handleSync()
              setMenuOpen(false)
            }}
            disabled={syncPending}
          >
            {syncPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <GitCommit className="mr-2 h-4 w-4" />
            )}
            Sync Now
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => {
              openChanges()
              setMenuOpen(false)
            }}
            disabled={!isConfigured}
          >
            <Eye className="mr-2 h-4 w-4" />
            View Changes
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => {
              openHistory()
              setMenuOpen(false)
            }}
            disabled={!isConfigured}
          >
            <History className="mr-2 h-4 w-4" />
            View History
          </DropdownMenuItem>
          <DropdownMenuItem disabled>
            <FileX className="mr-2 h-4 w-4" />
            Git Ignore
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onClick={() => {
              openConfig()
              setMenuOpen(false)
            }}
          >
            <Settings className="mr-2 h-4 w-4" />
            Settings
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <GitConfigDialog open={showConfig} onOpenChange={setShowConfig} />
      <GitChangesDialog open={showChanges} onOpenChange={setShowChanges} />
      <GitHistoryDialog open={showHistory} onOpenChange={setShowHistory} />
    </>
  )
}
