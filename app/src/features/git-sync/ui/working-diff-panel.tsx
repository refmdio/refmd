import { RefreshCw, GitBranch, AlignLeft, Columns2 } from 'lucide-react'
import React from 'react'

import type { GitDiffResult } from '@/shared/api'
import { GitDiffLineType } from '@/shared/api'
import { cn } from '@/shared/lib/utils'
import { Alert, AlertDescription } from '@/shared/ui/alert'
import { Button } from '@/shared/ui/button'
import { ScrollArea } from '@/shared/ui/scroll-area'

import { GitService as GitSvc } from '@/entities/git'

import { DiffViewer } from './diff-viewer'
import { FileExpander } from './file-expander'

type ViewMode = 'unified' | 'split'

type Props = { documentPath?: string; className?: string }

function getStats(diff: GitDiffResult): { additions: number; deletions: number } {
  let additions = 0
  let deletions = 0
  for (const l of diff.diff_lines || []) {
    if (l.line_type === GitDiffLineType.ADDED) additions++
    else if (l.line_type === GitDiffLineType.DELETED) deletions++
  }
  return { additions, deletions }
}

export function WorkingDiffPanel({ documentPath, className }: Props) {
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [diffs, setDiffs] = React.useState<GitDiffResult[]>([])
  const [viewMode, setViewMode] = React.useState<ViewMode>('unified')
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set())

  const load = React.useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const r = await GitSvc.getWorkingDiff()
      setDiffs(r)
      if (documentPath) {
        const match = r.filter((d) => d.file_path === documentPath).map((d) => d.file_path)
        setExpanded(new Set(match))
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to load diffs')
      setDiffs([])
    } finally {
      setLoading(false)
    }
  }, [documentPath])

  React.useEffect(() => { load() }, [load])

  const toggle = (fp: string) => {
    const s = new Set(expanded)
    s.has(fp) ? s.delete(fp) : s.add(fp)
    setExpanded(s)
  }

  const relevant = documentPath ? diffs.filter((d) => d.file_path === documentPath) : diffs
  const totalAdd = relevant.reduce((a, d) => a + getStats(d).additions, 0)
  const totalDel = relevant.reduce((a, d) => a + getStats(d).deletions, 0)

  if (loading) return <div className={cn('p-4', className)}>Loading...</div>
  if (error) return <Alert variant="destructive" className={cn('m-4', className)}><AlertDescription>{error}</AlertDescription></Alert>

  const hasChanges = relevant.length > 0

  return (
    <div className={cn('flex flex-col h-full min-h-0', className)}>
      <div className="p-4 border-b flex items-center justify-between flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-muted-foreground" />
            <h3 className="font-semibold text-lg">{documentPath ? 'File Changes' : 'Working Tree'}</h3>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            {documentPath ?? `${relevant.length} file${relevant.length !== 1 ? 's' : ''} with changes`}
          </p>
          {hasChanges && (
            <div className="flex items-center gap-3 text-sm mt-2">
              <span className="text-green-600 dark:text-green-400">+{totalAdd}</span>
              <span className="text-red-600 dark:text-red-400">-{totalDel}</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          <Button variant={viewMode === 'unified' ? 'secondary' : 'ghost'} size="sm" className="h-7 px-2 text-xs" onClick={() => setViewMode('unified')}><AlignLeft className="h-3 w-3 mr-1" />Unified</Button>
          <Button variant={viewMode === 'split' ? 'secondary' : 'ghost'} size="sm" className="h-7 px-2 text-xs" onClick={() => setViewMode('split')}><Columns2 className="h-3 w-3 mr-1" />Split</Button>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={load}><RefreshCw className="h-4 w-4" /></Button>
        </div>
      </div>
      <ScrollArea className="flex-1 min-h-0">
        {hasChanges ? (
          <div className="p-4 space-y-3">
            {relevant.map((d) => {
              const stats = getStats(d)
              const fp = d.file_path || ''
              const isExp = expanded.has(fp)
              return (
                <FileExpander key={fp} filePath={fp} isExpanded={isExp} onToggle={() => toggle(fp)} stats={stats}>
                  <div className="p-4">
                    <DiffViewer diffResult={d} viewMode={viewMode} showLineNumbers />
                  </div>
                </FileExpander>
              )
            })}
          </div>
        ) : (
          <div className="flex items-center justify-center h-full p-8 text-sm text-muted-foreground">No changes</div>
        )}
      </ScrollArea>
    </div>
  )
}
