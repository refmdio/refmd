import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { AlertCircle, CheckCircle, Eye, GitCommit, History, Loader2, RefreshCw, Settings } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { toast } from 'sonner'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { useAuthContext } from '@/features/auth'
import {
  syncWorkspaceToGit,
  pullFromGit,
  hasGitCredentials,
  getGitStatus,
  type ConflictItem,
} from '@/features/git-sync'

import GitChangesDialog from './git-changes-dialog'
import GitHistoryDialog from './git-history-dialog'
import GitPullDialog from './git-pull-dialog'

type Props = { className?: string; compact?: boolean }

interface GitStatusResult {
  initialized: boolean
  branch?: string
  changes: number
  ahead: number
  behind: number
}

function useGitSyncController() {
  const qc = useQueryClient()
  const isMobile = useIsMobile()
  const { activeWorkspaceId } = useAuthContext()

  const [showChanges, setShowChanges] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showPullDialog, setShowPullDialog] = useState(false)
  const [pullConflicts, setPullConflicts] = useState<ConflictItem[]>([])

  // Check if git credentials exist
  const {
    data: hasCredentials,
    isLoading: credentialsLoading,
  } = useQuery({
    queryKey: ['git-credentials', activeWorkspaceId],
    queryFn: () => activeWorkspaceId ? hasGitCredentials() : false,
    enabled: !!activeWorkspaceId,
  })

  // Get git status (client-side)
  const {
    data: status,
    isLoading: statusLoading,
    error: statusError,
  } = useQuery<GitStatusResult>({
    queryKey: ['git-status', activeWorkspaceId],
    queryFn: () => activeWorkspaceId ? getGitStatus(activeWorkspaceId) : { initialized: false, changes: 0, ahead: 0, behind: 0 },
    enabled: !!activeWorkspaceId && !!hasCredentials,
    refetchInterval: 30000,
    retry: false,
  })

  // Sync mutation (client-side)
  const syncMutation = useMutation({
    mutationFn: async () => {
      if (!activeWorkspaceId) throw new Error('No workspace selected')
      return syncWorkspaceToGit({ workspaceId: activeWorkspaceId })
    },
    onSuccess: (result) => {
      if (result.success) {
        toast.success(`${result.message}: ${result.filesChanged} files changed`)
      } else {
        toast.error(result.message)
      }
      qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
    },
    onError: (e: Error) => {
      toast.error(`Sync failed: ${e.message}`)
      qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
    },
  })

  // Pull mutation (client-side)
  const pullMutation = useMutation({
    mutationFn: async () => {
      if (!activeWorkspaceId) throw new Error('No workspace selected')
      return pullFromGit(activeWorkspaceId)
    },
    onSuccess: (result) => {
      if (result.success) {
        toast.success(result.message)
        qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
      } else if (result.conflicts.length > 0) {
        setPullConflicts(result.conflicts)
        setShowPullDialog(true)
      } else {
        toast.error(result.message)
      }
    },
    onError: (e: Error) => {
      toast.error(`Pull failed: ${e.message}`)
    },
  })

  const syncPending = syncMutation.isPending
  const hasChanges = (status?.changes || 0) > 0
  const isConfigured = !!hasCredentials && !!status?.initialized
  const canSync = isConfigured && !statusError
  const showButton = credentialsLoading || statusLoading || statusError || !!hasCredentials

  const handleSync = useCallback(() => {
    if (!isConfigured) return
    syncMutation.mutate()
  }, [isConfigured, syncMutation])

  const handlePull = useCallback(() => {
    if (!isConfigured) return
    pullMutation.mutate()
  }, [isConfigured, pullMutation])

  const openChanges = useCallback(() => {
    if (!status?.initialized) return
    setShowChanges(true)
  }, [status])

  const openHistory = useCallback(() => {
    if (!status?.initialized) return
    setShowHistory(true)
  }, [status])

  const statusErrorMessage = useMemo(() => {
    if (!statusError) return null
    return (statusError as Error)?.message || 'Failed to load Git status'
  }, [statusError])

  const statusText = useMemo(() => {
    if (credentialsLoading || statusLoading) return 'Loading…'
    if (statusError) return 'Status unavailable'
    if (!hasCredentials) return 'Configuration required'
    if (!status?.initialized) return 'Repository not initialized'
    if (hasChanges) return `${status.changes} changes`
    return 'Up to date'
  }, [hasCredentials, hasChanges, status, statusError, credentialsLoading, statusLoading])

  const tooltipText = useMemo(() => {
    if (statusError) return statusErrorMessage || 'Failed to load Git status'
    if (!hasCredentials) return 'Git configuration required'
    if (!status?.initialized) return 'Click to configure Git'
    if (hasChanges) return 'Click to sync changes'
    return 'Repository is up to date'
  }, [hasCredentials, hasChanges, status, statusError, statusErrorMessage])

  const icon = useMemo(() => {
    if (syncPending || credentialsLoading || statusLoading) return <Loader2 className="h-4 w-4 animate-spin" />
    if (statusError) return <AlertCircle className="h-4 w-4 text-destructive" />
    if (!hasCredentials || !status?.initialized) return <AlertCircle className="h-4 w-4 text-muted-foreground" />
    if (hasChanges) return <GitCommit className="h-4 w-4 text-orange-500" />
    return <CheckCircle className="h-4 w-4 text-emerald-500" />
  }, [hasCredentials, hasChanges, status, statusError, credentialsLoading, statusLoading, syncPending])

  return {
    isMobile,
    syncPending,
    canSync,
    icon,
    statusText,
    tooltipText,
    handleSync,
    handlePull,
    openChanges,
    openHistory,
    showChanges,
    setShowChanges,
    showHistory,
    setShowHistory,
    isConfigured,
    showButton,
    showPullDialog,
    setShowPullDialog,
    pullMutation,
    pullConflicts,
    setPullConflicts,
  }
}

export default function GitSyncButton({ className, compact = false }: Props) {
  const controller = useGitSyncController()
  const {
    isMobile,
    syncPending,
    canSync,
    icon,
    statusText,
    tooltipText,
    handleSync,
    handlePull,
    openChanges,
    openHistory,
    showChanges,
    setShowChanges,
    showHistory,
    setShowHistory,
    isConfigured,
    showButton,
    showPullDialog,
    setShowPullDialog,
    pullMutation,
    pullConflicts,
  } = controller

  const [menuOpen, setMenuOpen] = useState(false)
  if (!showButton) return null
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
            disabled={syncPending || !canSync}
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
              handlePull()
              setMenuOpen(false)
            }}
            disabled={!isConfigured || pullMutation.isPending}
          >
            {pullMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            Pull
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
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild onSelect={() => setMenuOpen(false)}>
            <Link to="/settings/git-sync">
              <Settings className="mr-2 h-4 w-4" />
              Open Settings
            </Link>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <GitChangesDialog open={showChanges} onOpenChange={setShowChanges} />
      <GitHistoryDialog open={showHistory} onOpenChange={setShowHistory} />
      <GitPullDialog
        open={showPullDialog}
        onOpenChange={setShowPullDialog}
        conflicts={pullConflicts}
        isLoading={pullMutation.isPending}
        onRetry={() => pullMutation.mutate()}
      />
    </>
  )
}
