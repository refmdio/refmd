import { useQuery, useQueryClient } from '@tanstack/react-query'
import { GitCommit as GitCommitIcon, RefreshCw, User, Clock, AlignLeft, Columns2 } from 'lucide-react'
import React from 'react'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Alert, AlertDescription } from '@/shared/ui/alert'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { DiffViewer } from '@/shared/ui/diff-viewer'
import { ScrollArea } from '@/shared/ui/scroll-area'

import { useAuthContext } from '@/features/auth'
import {
  getHistory,
  getCommitDiff,
  type GitCommitItem,
  type TextDiffLineType,
  type TextDiffResult,
} from '@/features/git-sync'

import { FileExpander } from './file-expander'

type Props = { open: boolean; onOpenChange: (open: boolean) => void }

const DIFF_LINE_TYPE = {
  ADDED: 'added' as TextDiffLineType,
  DELETED: 'deleted' as TextDiffLineType,
} as const

export default function GitHistoryDialog({ open, onOpenChange }: Props) {
  const qc = useQueryClient()
  const { activeWorkspaceId } = useAuthContext()
  const [selectedCommit, setSelectedCommit] = React.useState<GitCommitItem | null>(null)
  const [commitDiffs, setCommitDiffs] = React.useState<TextDiffResult[]>([])
  const [diffLoading, setDiffLoading] = React.useState(false)
  const [diffError, setDiffError] = React.useState<string | null>(null)
  const [viewMode, setViewMode] = React.useState<'unified' | 'split'>('unified')
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set())
  const isMobile = useIsMobile()
  const [mobileView, setMobileView] = React.useState<'list' | 'detail'>('list')
  React.useEffect(() => {
    if (open && activeWorkspaceId) {
      try { qc.removeQueries({ queryKey: ['git-history', activeWorkspaceId] }) } catch {}
      qc.prefetchQuery({ queryKey: ['git-history', activeWorkspaceId], queryFn: () => getHistory(activeWorkspaceId) })
    }
  }, [open, qc, activeWorkspaceId])

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['git-history', activeWorkspaceId],
    queryFn: () => activeWorkspaceId ? getHistory(activeWorkspaceId) : [],
    enabled: open && !!activeWorkspaceId,
    refetchOnMount: 'always',
    staleTime: 0,
    retry: false,
  })

  React.useEffect(() => {
    if (!open) {
      setMobileView('list')
      return
    }
    if (!isMobile) {
      setMobileView('list')
    }
  }, [open, isMobile])

  React.useEffect(() => {
    if (!isMobile) return
    if (!selectedCommit) {
      setMobileView('list')
    }
  }, [isMobile, selectedCommit])

  const commits: GitCommitItem[] = data ?? []

  const fetchCommitDiffs = React.useCallback(async (commit: GitCommitItem) => {
    if (!activeWorkspaceId) return
    try {
      setDiffLoading(true)
      setDiffError(null)
      setCommitDiffs([])
      const parent = commit.hash + '^'
      const r = await getCommitDiff(activeWorkspaceId, parent, commit.hash)
      setCommitDiffs(r)
      setExpanded(new Set(r.map((d) => d.file_path)))
    } catch (e: any) {
      setDiffError(e?.message || 'Failed to load commit changes')
    } finally {
      setDiffLoading(false)
    }
  }, [activeWorkspaceId])

  const selectCommit = React.useCallback(
    (commit: GitCommitItem) => {
      setSelectedCommit(commit)
      fetchCommitDiffs(commit)
      if (isMobile) {
        setMobileView('detail')
      }
    },
    [fetchCommitDiffs, isMobile],
  )

  React.useEffect(() => {
    if (!selectedCommit && commits.length > 0) {
      const last = commits[commits.length - 1]
      setSelectedCommit(last)
      fetchCommitDiffs(last)
    }
  }, [commits, selectedCommit, fetchCommitDiffs])

  const toggle = (fp: string) => {
    const s = new Set(expanded)
    s.has(fp) ? s.delete(fp) : s.add(fp)
    setExpanded(s)
  }

  const historyListContent = (
    <div className="flex h-full w-full flex-col">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <h3 className="text-sm font-medium">Commits</h3>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => qc.invalidateQueries({ queryKey: ['git-history', activeWorkspaceId] })}
          disabled={isLoading}
        >
          <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
        </Button>
      </div>
      <ScrollArea className={cn('flex-1 min-h-0', isMobile ? 'max-h-[65vh]' : 'max-h-none')}>
        <div className="min-w-0 space-y-3 p-4">
          {(isLoading || (open && isFetching && !data && !error)) && (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          )}
          {!isLoading && commits.length === 0 && (
            <div className="py-8 text-center text-muted-foreground">No commits yet</div>
          )}
          {!isLoading && commits.map((c) => (
            <div
              key={c.hash}
              className={cn(
                'cursor-pointer overflow-hidden rounded-lg border p-4 transition-colors',
                selectedCommit?.hash === c.hash ? 'border-accent-foreground/20 bg-accent' : 'hover:bg-accent/50',
              )}
              onClick={() => selectCommit(c)}
            >
              <div className="flex items-start gap-2">
                <GitCommitIcon className="h-4 w-4 text-muted-foreground" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <code className="text-xs font-mono text-muted-foreground">{c.hash.slice(0, 7)}</code>
                    <span className="text-xs text-muted-foreground">{new Date(c.time).toLocaleString()}</span>
                  </div>
                  <div className="block text-sm font-medium">{(c.message || '').split('\n')[0] || '(no message)'}</div>
                  <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <User className="h-3 w-3" />
                      {c.author_name} &lt;{c.author_email}&gt;
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  )

  const detailContent = (
    <div className="flex h-full w-full min-w-0 flex-col">
      <div className="flex items-center justify-between border-b p-4">
        <div>
          <h3 className="mb-1 text-lg font-semibold">Commit {selectedCommit?.hash?.slice(0, 7) ?? ''}</h3>
          <p className="mb-2 text-sm text-muted-foreground">{selectedCommit?.message?.split('\n')[0] ?? ''}</p>
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <User className="h-3 w-3" />
              {selectedCommit?.author_name ?? ''}
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {selectedCommit?.time ? new Date(selectedCommit.time).toLocaleString() : ''}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant={viewMode === 'unified' ? 'secondary' : 'ghost'}
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => setViewMode('unified')}
          >
            <AlignLeft className="mr-1 h-3 w-3" />
            Unified
          </Button>
          <Button
            variant={viewMode === 'split' ? 'secondary' : 'ghost'}
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => setViewMode('split')}
          >
            <Columns2 className="mr-1 h-3 w-3" />
            Split
          </Button>
        </div>
      </div>
      <ScrollArea className="flex-1 min-h-0 min-w-0">
        <div className="min-w-0 space-y-3 p-4">
          {diffLoading && (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          )}
          {diffError && (
            <Alert variant="destructive">
              <AlertDescription>{diffError}</AlertDescription>
            </Alert>
          )}
          {!diffLoading && !diffError && commitDiffs.length === 0 && (
            <div className="py-8 text-center text-muted-foreground">
              {selectedCommit ? 'No changes in this commit' : 'Select a commit'}
            </div>
          )}
          {!diffLoading && !diffError && commitDiffs.length > 0 && (
            <div className="space-y-3">
              {commitDiffs.map((d) => {
                const fp = d.file_path || ''
                const isExp = expanded.has(fp)
                const adds = d.diff_lines.filter((l) => l.line_type === DIFF_LINE_TYPE.ADDED).length
                const dels = d.diff_lines.filter((l) => l.line_type === DIFF_LINE_TYPE.DELETED).length
                return (
                  <FileExpander key={fp} filePath={fp} isExpanded={isExp} onToggle={() => toggle(fp)} stats={{ additions: adds, deletions: dels }}>
                    <div className="p-4 overflow-auto">
                      <DiffViewer diffResult={d} viewMode={viewMode} />
                    </div>
                  </FileExpander>
                )
              })}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('sm:max-w-[85vw] max-w-[95vw] h-[90vh] p-0 flex flex-col', overlayPanelClass)}>
        <DialogHeader className="px-6 py-4 border-b flex-shrink-0">
          <DialogTitle>Git History</DialogTitle>
        </DialogHeader>
        <div className="flex-1 overflow-hidden">
          {error && (
            <Alert variant="destructive" className="m-4"><AlertDescription>Failed to load history</AlertDescription></Alert>
          )}
          {!error && (
            <div className="flex h-full min-w-0">
              {isMobile ? (
                <div className="flex h-full w-full flex-col">
                  {mobileView === 'list' && (
                    <>
                      {historyListContent}
                      {selectedCommit && (
                        <div className="border-t px-4 py-3">
                          <Button className="w-full" variant="secondary" onClick={() => setMobileView('detail')}>
                            View commit details
                          </Button>
                        </div>
                      )}
                    </>
                  )}
                  {mobileView === 'detail' && (
                    <div className="flex h-full flex-col">
                      <div className="border-b px-4 py-3">
                        <Button variant="ghost" size="sm" onClick={() => setMobileView('list')}>
                          ← Back to commits
                        </Button>
                      </div>
                      {detailContent}
                    </div>
                  )}
                </div>
              ) : (
                <div className="grid h-full w-full min-w-0 grid-cols-[minmax(240px,360px)_1fr]">
                  <div className="border-r">{historyListContent}</div>
                  <div className="flex h-full min-w-0 flex-col">{detailContent}</div>
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
