import { useQuery, useQueryClient } from '@tanstack/react-query'
import { GitCommit as GitCommitIcon, RefreshCw, User, Clock, AlignLeft, Columns2 } from 'lucide-react'
import React from 'react'

import type { GitCommitItem, GitDiffResult } from '@/shared/api'
import { GitDiffLineType } from '@/shared/api'
import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Alert, AlertDescription } from '@/shared/ui/alert'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/shared/ui/resizable'
import { ScrollArea } from '@/shared/ui/scroll-area'

import { GitService as GitSvc } from '@/entities/git'

import { DiffViewer } from './diff-viewer'
import { FileExpander } from './file-expander'

type Props = { open: boolean; onOpenChange: (open: boolean) => void }

export default function GitHistoryDialog({ open, onOpenChange }: Props) {
  const qc = useQueryClient()
  const [selectedCommit, setSelectedCommit] = React.useState<GitCommitItem | null>(null)
  const [commitDiffs, setCommitDiffs] = React.useState<GitDiffResult[]>([])
  const [diffLoading, setDiffLoading] = React.useState(false)
  const [diffError, setDiffError] = React.useState<string | null>(null)
  const [viewMode, setViewMode] = React.useState<'unified' | 'split'>('unified')
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set())
  React.useEffect(() => {
    if (open) {
      try { qc.removeQueries({ queryKey: ['git-history'] }) } catch {}
      qc.prefetchQuery({ queryKey: ['git-history'], queryFn: () => GitSvc.getHistory() })
    }
  }, [open, qc])

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['git-history'],
    queryFn: () => GitSvc.getHistory(),
    enabled: open,
    refetchOnMount: 'always',
    staleTime: 0,
    retry: false,
  })

  const commits: GitCommitItem[] = data?.commits ?? []

  const fetchCommitDiffs = React.useCallback(async (commit: GitCommitItem) => {
    try {
      setDiffLoading(true)
      setDiffError(null)
      setCommitDiffs([])
      const parent = commit.hash + '^'
      const r = await GitSvc.getCommitDiff({ from: parent, to: commit.hash })
      setCommitDiffs(r)
      setExpanded(new Set(r.map((d) => d.file_path)))
    } catch (e: any) {
      setDiffError(e?.message || 'Failed to load commit changes')
    } finally {
      setDiffLoading(false)
    }
  }, [])

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
            <ResizablePanelGroup direction="horizontal" className="h-full">
              <ResizablePanel defaultSize={30} minSize={20} maxSize={50}>
                <div className="flex flex-col h-full min-h-0">
                  <div className="flex items-center justify-between px-4 py-2 border-b flex-shrink-0">
                    <h3 className="text-sm font-medium">Commits</h3>
                    <Button variant="ghost" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ['git-history'] })} disabled={isLoading}>
                      <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
                    </Button>
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    <div className="p-4 space-y-3">
                      {(isLoading || (open && isFetching && !data && !error)) && (
                        <div className="flex justify-center items-center py-8"><RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" /></div>
                      )}
                      {!isLoading && commits.length === 0 && (<div className="text-center py-8 text-muted-foreground">No commits yet</div>)}
                      {!isLoading && commits.map((c) => (
                        <div
                          key={c.hash}
                          className={cn('border rounded-lg p-4 cursor-pointer transition-colors', selectedCommit?.hash === c.hash ? 'bg-accent border-accent-foreground/20' : 'hover:bg-accent/50')}
                          onClick={() => { setSelectedCommit(c); fetchCommitDiffs(c) }}
                        >
                          <div className="flex items-start gap-2">
                            <GitCommitIcon className="h-4 w-4 text-muted-foreground" />
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <code className="text-xs font-mono text-muted-foreground">{c.hash.slice(0, 7)}</code>
                                <span className="text-xs text-muted-foreground">{new Date(c.time).toLocaleString()}</span>
                              </div>
                              <div className="font-medium text-sm truncate">{(c.message || '').split('\n')[0] || '(no message)'}</div>
                              <div className="text-xs text-muted-foreground flex items-center gap-2">
                                <span className="truncate flex items-center gap-1"><User className="h-3 w-3" />{c.author_name} &lt;{c.author_email}&gt;</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </ResizablePanel>
              <ResizableHandle />
              <ResizablePanel defaultSize={70}>
                <div className="h-full flex flex-col min-h-0">
                  <div className="p-4 border-b flex items-center justify-between flex-shrink-0">
                    <div>
                      <h3 className="font-semibold text-lg mb-1">Commit {selectedCommit?.hash?.slice(0, 7) ?? ''}</h3>
                      <p className="text-sm text-muted-foreground mb-2">{selectedCommit?.message?.split('\n')[0] ?? ''}</p>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span className="flex items-center gap-1"><User className="h-3 w-3" />{selectedCommit?.author_name ?? ''}</span>
                        <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{selectedCommit?.time ? new Date(selectedCommit.time).toLocaleString() : ''}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button variant={viewMode === 'unified' ? 'secondary' : 'ghost'} size="sm" className="h-7 px-2 text-xs" onClick={() => setViewMode('unified')}><AlignLeft className="h-3 w-3 mr-1" />Unified</Button>
                      <Button variant={viewMode === 'split' ? 'secondary' : 'ghost'} size="sm" className="h-7 px-2 text-xs" onClick={() => setViewMode('split')}><Columns2 className="h-3 w-3 mr-1" />Split</Button>
                    </div>
                  </div>
                  <ScrollArea className="flex-1 min-h-0">
                    <div className="p-4">
                      {diffLoading && (<div className="flex justify-center items-center py-8"><RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" /></div>)}
                      {diffError && (<Alert variant="destructive"><AlertDescription>{diffError}</AlertDescription></Alert>)}
                      {!diffLoading && !diffError && commitDiffs.length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">{selectedCommit ? 'No changes in this commit' : 'Select a commit'}</div>
                      )}
                      {!diffLoading && !diffError && commitDiffs.length > 0 && (
                        <div className="space-y-3">
                          {commitDiffs.map((d) => {
                            const fp = d.file_path || ''
                            const isExp = expanded.has(fp)
                            const adds = d.diff_lines.filter((l) => l.line_type === GitDiffLineType.ADDED).length
                            const dels = d.diff_lines.filter((l) => l.line_type === GitDiffLineType.DELETED).length
                            return (
                              <FileExpander key={fp} filePath={fp} isExpanded={isExp} onToggle={() => toggle(fp)} stats={{ additions: adds, deletions: dels }}>
                                <div className="p-4">
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
              </ResizablePanel>
            </ResizablePanelGroup>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
