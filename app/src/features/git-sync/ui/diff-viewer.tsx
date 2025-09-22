import type { GitDiffResult, GitDiffLine } from '@/shared/api'
import { GitDiffLineType } from '@/shared/api'
import { cn } from '@/shared/lib/utils'

type ViewMode = 'unified' | 'split'

type Props = {
  diffResult: GitDiffResult
  viewMode?: ViewMode
  showLineNumbers?: boolean
  className?: string
}

export function DiffViewer({ diffResult, viewMode = 'unified', showLineNumbers = true, className }: Props) {
  if (!diffResult.diff_lines || diffResult.diff_lines.length === 0) {
    return <div className={cn('text-center py-4 text-muted-foreground', className)}>No changes to display</div>
  }
  if (viewMode === 'split') {
    return <SplitDiffView diffResult={diffResult} showLineNumbers={showLineNumbers} className={className} />
  }
  return <UnifiedDiffView diffResult={diffResult} showLineNumbers={showLineNumbers} className={className} />
}

function UnifiedDiffView({ diffResult, showLineNumbers, className }: { diffResult: GitDiffResult; showLineNumbers: boolean; className?: string }) {
  return (
    <div className={cn('font-mono text-sm overflow-x-auto', className)}>
      {(diffResult.diff_lines || []).map((line, idx) => (
        <div
          key={idx}
          className={cn(
            'flex',
            line.line_type === GitDiffLineType.ADDED && 'bg-green-50 dark:bg-green-950/30',
            line.line_type === GitDiffLineType.DELETED && 'bg-red-50 dark:bg-red-950/30',
            line.line_type === GitDiffLineType.CONTEXT && 'bg-background'
          )}
        >
          {showLineNumbers && (
            <>
              <span className="px-2 text-muted-foreground text-xs w-12 text-right select-none">{line.old_line_number || ''}</span>
              <span className="px-2 text-muted-foreground text-xs w-12 text-right select-none">{line.new_line_number || ''}</span>
            </>
          )}
          <span
            className={cn(
              'px-2 select-none',
              line.line_type === GitDiffLineType.ADDED && 'text-green-600 dark:text-green-400',
              line.line_type === GitDiffLineType.DELETED && 'text-red-600 dark:text-red-400',
              line.line_type === GitDiffLineType.CONTEXT && 'text-muted-foreground'
            )}
          >
            {line.line_type === GitDiffLineType.ADDED ? '+' : line.line_type === GitDiffLineType.DELETED ? '-' : ' '}
          </span>
          <span className="flex-1 whitespace-pre">{line.content}</span>
        </div>
      ))}
    </div>
  )
}

function SplitDiffView({ diffResult, showLineNumbers, className }: { diffResult: GitDiffResult; showLineNumbers: boolean; className?: string }) {
  const processed: Array<{ old?: GitDiffLine; new?: GitDiffLine }> = []
  const lines = diffResult.diff_lines || []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (line.line_type === GitDiffLineType.CONTEXT) {
      processed.push({ old: line, new: line })
      i++
    } else if (line.line_type === GitDiffLineType.DELETED) {
      let j = i + 1
      while (j < lines.length && lines[j].line_type === GitDiffLineType.DELETED) j++
      if (j < lines.length && lines[j].line_type === GitDiffLineType.ADDED) {
        const deletedBatch = lines.slice(i, j)
        let k = j
        deletedBatch.forEach((del) => {
          if (k < lines.length && lines[k].line_type === GitDiffLineType.ADDED) {
            processed.push({ old: del, new: lines[k] })
            k++
          } else {
            processed.push({ old: del })
          }
        })
        while (k < lines.length && lines[k].line_type === GitDiffLineType.ADDED) {
          processed.push({ new: lines[k] })
          k++
        }
        i = k
      } else {
        processed.push({ old: line })
        i++
      }
    } else if (line.line_type === GitDiffLineType.ADDED) {
      processed.push({ new: line })
      i++
    } else {
      i++
    }
  }

  return (
    <div className={cn('font-mono text-sm overflow-x-auto', className)}>
      <div className="flex">
        <div className="flex-1 border-r overflow-x-auto">
          {processed.map((pair, idx) => (
            <div
              key={`old-${idx}`}
              className={cn(
                'flex min-h-[1.5rem]',
                pair.old?.line_type === GitDiffLineType.DELETED && 'bg-red-50 dark:bg-red-950/30',
                pair.old?.line_type === GitDiffLineType.CONTEXT && 'bg-background',
                !pair.old && 'bg-muted/20'
              )}
            >
              {showLineNumbers && (
                <span className="px-2 text-muted-foreground text-xs w-12 text-right select-none">{pair.old?.old_line_number || ''}</span>
              )}
              {pair.old && (
                <>
                  <span className={cn('px-2 select-none', pair.old.line_type === GitDiffLineType.DELETED && 'text-red-600 dark:text-red-400', pair.old.line_type === GitDiffLineType.CONTEXT && 'text-muted-foreground')}>
                    {pair.old.line_type === GitDiffLineType.DELETED ? '-' : ' '}
                  </span>
                  <span className="flex-1 whitespace-pre overflow-x-auto">{pair.old.content}</span>
                </>
              )}
            </div>
          ))}
        </div>
        <div className="flex-1 overflow-x-auto">
          {processed.map((pair, idx) => (
            <div
              key={`new-${idx}`}
              className={cn(
                'flex min-h-[1.5rem]',
                pair.new?.line_type === GitDiffLineType.ADDED && 'bg-green-50 dark:bg-green-950/30',
                pair.new?.line_type === GitDiffLineType.CONTEXT && 'bg-background',
                !pair.new && 'bg-muted/20'
              )}
            >
              {showLineNumbers && (
                <span className="px-2 text-muted-foreground text-xs w-12 text-right select-none">{pair.new?.new_line_number || ''}</span>
              )}
              {pair.new && (
                <>
                  <span className={cn('px-2 select-none', pair.new.line_type === GitDiffLineType.ADDED && 'text-green-600 dark:text-green-400', pair.new.line_type === GitDiffLineType.CONTEXT && 'text-muted-foreground')}>
                    {pair.new.line_type === GitDiffLineType.ADDED ? '+' : ' '}
                  </span>
                  <span className="flex-1 whitespace-pre overflow-x-auto">{pair.new.content}</span>
                </>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
