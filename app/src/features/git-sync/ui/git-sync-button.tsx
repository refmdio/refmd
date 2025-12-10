import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { AlertCircle, CheckCircle, Eye, FileX, GitCommit, History, Loader2, RefreshCw, Settings } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'

import type { GitPullConflictItem, GitPullResolution, GitPullSessionResponse } from '@/shared/api'
import { ApiError } from '@/shared/api'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { getStatus, getConfig, syncNow, initRepository, startPullSession, resolvePullSession, finalizePullSession, getPullSession } from '@/entities/git'

import { setConflicts as setGlobalConflicts, readConflicts, clearResolutions, setSessionId, readSessionId, clearSession, readResolutions } from '@/features/git-sync/lib/git-conflict-store'

import GitChangesDialog from './git-changes-dialog'
import GitHistoryDialog from './git-history-dialog'
import GitPullDialog from './git-pull-dialog'

type Props = { className?: string; compact?: boolean }

type GitStatus = Awaited<ReturnType<typeof getStatus>>
type GitConfig = Awaited<ReturnType<typeof getConfig>>

function useGitSyncController() {
  const qc = useQueryClient()
  const isMobile = useIsMobile()
  const [showChanges, setShowChanges] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showPullDialog, setShowPullDialog] = useState(false)
  const [pullConflicts, setPullConflicts] = useState<GitPullConflictItem[]>(() => readConflicts())
  const [emptyConflictWarning, setEmptyConflictWarning] = useState(false)
  const [polling, setPolling] = useState(false)
  const [sessionId, setSessionIdState] = useState<string | null>(() => readSessionId())

  useEffect(() => {
    const handler = () => setSessionIdState(readSessionId())
    window.addEventListener('storage', handler)
    window.addEventListener('refmd:git-conflicts-updated', handler as any)
    return () => {
      window.removeEventListener('storage', handler)
      window.removeEventListener('refmd:git-conflicts-updated', handler as any)
    }
  }, [])

  const extractConflicts = useCallback((value: unknown): GitPullConflictItem[] => {
    const fromArray = (arr: unknown): GitPullConflictItem[] => (Array.isArray(arr) ? (arr as GitPullConflictItem[]) : [])
    if (!value) return []
    if (Array.isArray(value)) return fromArray(value)
    if (typeof value === 'object') {
      const maybeArr = (value as any)?.conflicts
      if (Array.isArray(maybeArr)) return fromArray(maybeArr)
    }
    return []
  }, [])

  const updateConflicts = useCallback(
    (list: GitPullConflictItem[] | null | undefined, options?: { allowClear?: boolean }) => {
      const safeList = Array.isArray(list) ? list : []
      if (safeList.length === 0 && !options?.allowClear) {
        // Keep existing list/cached conflicts when server returns empty unexpectedly
        return
      }
      setPullConflicts(safeList)
      setGlobalConflicts(safeList)
      if (safeList.length === 0) {
        clearResolutions()
      }
      if (safeList.length > 0) {
        setEmptyConflictWarning(false)
      }
    },
    [],
  )

  const {
    data: status,
    isLoading: statusLoading,
    error: statusError,
  } = useQuery<GitStatus, unknown>({ queryKey: ['git-status'], queryFn: () => getStatus(), refetchInterval: 10000, retry: false })
  const { data: config } = useQuery<GitConfig>({ queryKey: ['git-config'], queryFn: () => getConfig(), retry: false })

  const syncMutation = useMutation({
    mutationFn: () => syncNow({ requestBody: { message: undefined } }),
    onSuccess: (data: any) => {
      const ok = !!data?.success
      const changed = data?.files_changed ?? 0
      const msg = data?.message || 'Sync completed'
      if (ok) toast.success(`${msg}: ${changed} files changed`)
      // Do not surface push failures in toast; rely on status panel instead
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
    onError: (e: any) => {
      const raw = e?.body?.message || e?.message || `${e}`
      const lower = typeof raw === 'string' ? raw.toLowerCase() : ''
      if (lower.includes('git_repo_not_found') || lower.includes('repo_not_found') || lower.includes('git_http_not_found')) {
        toast.error('Git sync failed: repository URL or branch was not found. Please check the URL/branch and try again.')
      } else if (lower.includes('git_auth_redirect') || lower.includes('too many redirects') || lower.includes('http (34)')) {
        toast.error('Git sync failed: remote requires re-authentication. Please re-enter your token/SSH key and ensure SSO is approved.')
      } else if (e?.status === 409) {
        toast.error('Remote is ahead. Pull and resolve conflicts before syncing.')
        const extracted = extractConflicts((e as any)?.body)
        const fallback = extracted.length ? extracted : readConflicts()
        updateConflicts(fallback)
        if (!extracted.length && !fallback.length) {
          setEmptyConflictWarning(true)
        }
        setShowPullDialog(true)
        pullMutation.mutate({ resolutions: [] })
      } else {
        toast.error(`Sync failed: ${raw}`)
      }
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

  const pullMutation = useMutation({
    mutationFn: async (payload?: { resolutions?: GitPullResolution[] }) => {
      const sid = sessionId ?? readSessionId()
      if (sid) {
        const resolutions = payload?.resolutions ?? readResolutions()
        const res = await resolvePullSession({ id: sid, requestBody: { resolutions } })
        return { kind: 'resolve' as const, res }
      }
      const res = await startPullSession()
      return { kind: 'start' as const, res }
    },
    onSuccess: (data) => {
      const res = data.res as GitPullSessionResponse
      if ((res as any)?.status === 'stale') {
        clearSession()
        clearResolutions()
        setGlobalConflicts([])
        setEmptyConflictWarning(true)
        toast.error('Pull session expired. Please pull again.')
        qc.invalidateQueries({ queryKey: ['git-status'] })
        return
      }
      const conflicts = res.conflicts ?? []
      const hasConflicts = conflicts.length > 0
      setSessionId(res.session_id)
      setSessionIdState(res.session_id)
      if (hasConflicts) {
        clearResolutions()
        updateConflicts(conflicts)
        setEmptyConflictWarning(false)
        setShowPullDialog(true)
        return
      }
      // no conflicts
      clearSession()
      updateConflicts([], { allowClear: true })
      setEmptyConflictWarning(false)
      finalizePullSession({ id: res.session_id })
        .catch(() => {
          /* ignore finalize failure; user can retry */
        })
        .finally(() => {
          toast.success('Pull completed')
          qc.invalidateQueries({ queryKey: ['git-status'] })
        })
    },
    onError: (e: any) => {
      const bodyConflicts = extractConflicts((e as any)?.body)
      const statusField = (e as any)?.body?.status
      const msg = (e as any)?.body?.message || ''
      if (statusField === 'stale' || typeof msg === 'string' && msg.toLowerCase().includes('stale')) {
        clearSession()
        clearResolutions()
        updateConflicts([], { allowClear: true })
        setEmptyConflictWarning(true)
        toast.error('Pull session expired. Please pull again.')
        qc.invalidateQueries({ queryKey: ['git-status'] })
        return
      }
      if (e instanceof ApiError && e.status === 409 && bodyConflicts.length > 0) {
        const sid = (e as any)?.body?.session_id || readSessionId()
        setSessionId(sid)
        setSessionIdState(sid)
        clearResolutions()
        updateConflicts(bodyConflicts)
        setShowPullDialog(true)
        return
      }
      if (e instanceof ApiError && e.status === 409) {
        clearResolutions()
        updateConflicts(readConflicts())
        setEmptyConflictWarning(true)
        toast.error('Conflicts reported but server returned no list.')
        setShowPullDialog(true)
        return
      }
      const detail = e?.body?.message || e?.message || `${e}`
      toast.error(`Pull failed: ${detail}`)
    },
  })

  const syncPending = syncMutation.isPending || initMutation.isPending
  const hasChanges = ((status?.uncommitted_changes || 0) + (status?.untracked_files || 0)) > 0
  const isConfigured = Boolean(config) && Boolean(status?.repository_initialized)
  const canSync = isConfigured && !statusError
  const showButton = statusLoading || statusError || Boolean(status?.repository_initialized)

  const handleSync = useCallback(() => {
    if (!config || !status?.repository_initialized) return
    syncMutation.mutate()
  }, [config, status, syncMutation])

  const openChanges = useCallback(() => {
    if (!status?.repository_initialized) return
    setShowChanges(true)
  }, [status])
  const openHistory = useCallback(() => {
    if (!status?.repository_initialized) return
    setShowHistory(true)
  }, [status])

  const statusErrorMessage = useMemo(() => {
    if (!statusError) return null
    const raw = (statusError as any)?.body?.message || (statusError as any)?.message || `${statusError}`
    return raw || 'Failed to load Git status'
  }, [statusError])

  const statusText = useMemo(() => {
    if (statusLoading) return 'Loading…'
    if (statusError) return 'Status unavailable'
    if (!config) return 'Configuration required'
    if (!status?.repository_initialized) return 'Repository not initialized'
    if (hasChanges) return `${(status?.uncommitted_changes || 0) + (status?.untracked_files || 0)} changes`
    if (status?.has_remote && status?.last_sync_status === 'error') return 'Push failed'
    return 'Up to date'
  }, [config, hasChanges, status, statusError, statusLoading])

  const tooltipText = useMemo(() => {
    if (statusError) return statusErrorMessage || 'Failed to load Git status'
    if (!config) return 'Git configuration required'
    if (!status?.repository_initialized) return 'Click to configure Git'
    if (hasChanges) return 'Click to sync changes'
    if (status?.has_remote && status?.last_sync_status === 'error') return status?.last_sync_message || 'Last push failed'
    return 'Repository is up to date'
  }, [config, hasChanges, status, statusError, statusErrorMessage])

  const icon = useMemo(() => {
    if (syncPending || statusLoading) return <Loader2 className="h-4 w-4 animate-spin" />
    if (statusError) return <AlertCircle className="h-4 w-4 text-destructive" />
    if (!config || !status?.repository_initialized) return <AlertCircle className="h-4 w-4 text-muted-foreground" />
    if (!hasChanges && status?.has_remote && status?.last_sync_status === 'error') return <AlertCircle className="h-4 w-4 text-destructive" />
    if (hasChanges) return <GitCommit className="h-4 w-4 text-orange-500" />
    return <CheckCircle className="h-4 w-4 text-emerald-500" />
  }, [config, hasChanges, status, statusError, statusLoading, syncPending])

  useEffect(() => {
    const sid = sessionId ?? readSessionId()
    if (!sid) return
    setPolling(true)
    const timer = window.setInterval(() => {
      getPullSession({ id: sid })
        .then((session) => {
          if ((session as any)?.status === 'stale') {
            clearSession()
            clearResolutions()
            setGlobalConflicts([])
            setEmptyConflictWarning(true)
            toast.error('Pull session expired. Please pull again.')
            return
          }
          setSessionId(session.session_id)
          updateConflicts(session.conflicts ?? [], { allowClear: true })
        })
        .catch(() => {})
    }, 10000)
    return () => {
      window.clearInterval(timer)
      setPolling(false)
    }
  }, [sessionId, updateConflicts])

  return {
    sessionId,
    polling,
    isMobile,
    syncPending,
    canSync,
    icon,
    statusText,
    tooltipText,
    handleSync,
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
    updateConflicts,
    emptyConflictWarning,
  }
}

export default function GitSyncButton({ className, compact = false }: Props) {
  const controller = useGitSyncController()
  const {
    sessionId,
    polling,
    isMobile,
    syncPending,
    canSync,
    icon,
    statusText,
    tooltipText,
    handleSync,
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
    updateConflicts,
    emptyConflictWarning,
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
                  <p className="truncate text-xs text-muted-foreground/80">
                    {polling ? 'Synchronizing conflicts…' : statusText}
                  </p>
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
              clearResolutions()
              updateConflicts(readConflicts(), { allowClear: true })
              setShowPullDialog(true)
              pullMutation.mutate({ resolutions: [] })
              setMenuOpen(false)
            }}
            disabled={!isConfigured || pullMutation.isPending}
          >
            {pullMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            Pull (resolve conflicts)
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
        emptyWarning={emptyConflictWarning}
        sessionId={sessionId}
        onResolve={(resolutions) => pullMutation.mutate({ resolutions })}
        onRetry={() => pullMutation.mutate({ resolutions: [] })}
      />
    </>
  )
}
