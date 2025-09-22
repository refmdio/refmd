import { RefreshCw } from 'lucide-react'
import React from 'react'

import type { GitDiffResult } from '@/shared/api'
import { GitDiffLineType } from '@/shared/api'
import { cn } from '@/shared/lib/utils'
import { Alert, AlertDescription } from '@/shared/ui/alert'
import { Button } from '@/shared/ui/button'
import { ScrollArea } from '@/shared/ui/scroll-area'

import { fetchCommitDiff } from '@/entities/git'

import { DiffViewer } from './diff-viewer'
import { FileExpander } from './file-expander'

type ViewMode = 'unified' | 'split'

type Props = { commitId: string; className?: string }

function getStats(diff: GitDiffResult): { additions: number; deletions: number } {
  let additions = 0
  let deletions = 0
  for (const l of diff.diff_lines || []) {
    if (l.line_type === GitDiffLineType.ADDED) additions++
    else if (l.line_type === GitDiffLineType.DELETED) deletions++
  }
  return { additions, deletions }
}

export function CommitDiffPanel({ commitId, className }: Props) {
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [diffs, setDiffs] = React.useState<GitDiffResult[]>([])
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = React.useState<ViewMode>('unified')

  const load = React.useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const parent = commitId + '^'
      const r = await fetchCommitDiff(parent, commitId)
      setDiffs(r)
      setExpanded(new Set(r.map((d) => d.file_path)))
    } catch (e: any) {
      setError(e?.message || 'Failed to load commit diff')
      setDiffs([])
    } finally {
      setLoading(false)
    }
  }, [commitId])

  React.useEffect(() => { load() }, [load])

  const toggle = (fp: string) => {
    const s = new Set(expanded)
    s.has(fp) ? s.delete(fp) : s.add(fp)
    setExpanded(s)
  }

  if (loading) return <div className={cn('p-4', className)}>Loading...</div>
  if (error) return <Alert variant="destructive" className={cn('m-4', className)}><AlertDescription>{error}</AlertDescription></Alert>
  if (!diffs.length) return <div className={cn('p-8 text-center text-muted-foreground', className)}>No changes in this commit</div>

  return (
    <ScrollArea className={cn('h-full', className)}>
      <div className="space-y-4 p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium">{diffs.length} file{diffs.length !== 1 ? 's' : ''} changed</h3>
          <div className="flex items-center gap-1">
            <Button variant={viewMode === 'unified' ? 'secondary' : 'ghost'} size="sm" className="h-7 px-2 text-xs" onClick={() => setViewMode('unified')}>Unified</Button>
            <Button variant={viewMode === 'split' ? 'secondary' : 'ghost'} size="sm" className="h-7 px-2 text-xs" onClick={() => setViewMode('split')}>Split</Button>
            <Button variant="ghost" size="sm" onClick={load}><RefreshCw className="h-4 w-4" /></Button>
          </div>
        </div>
        {diffs.map((d) => {
          const stats = getStats(d)
          const fp = d.file_path || ''
          const isExp = expanded.has(fp)
          return (
            <FileExpander key={fp} filePath={fp} isExpanded={isExp} onToggle={() => toggle(fp)} stats={stats}>
              {d.diff_lines && d.diff_lines.length > 0 && (
                <div className="p-4">
                  <DiffViewer diffResult={d} viewMode={viewMode} />
                </div>
              )}
            </FileExpander>
          )
        })}
      </div>
    </ScrollArea>
  )
}
