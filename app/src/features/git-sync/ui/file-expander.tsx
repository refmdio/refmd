import { ChevronDown, ChevronRight, FileText } from 'lucide-react'
import React from 'react'

import { cn } from '@/shared/lib/utils'

type Props = {
  filePath: string
  isExpanded: boolean
  onToggle: () => void
  stats?: { additions: number; deletions: number }
  className?: string
  children?: React.ReactNode
}

export function FileExpander({ filePath, isExpanded, onToggle, stats, className, children }: Props) {
  return (
    <div className={cn('border rounded-lg', className)}>
      <button className="w-full flex items-center gap-2 p-3 hover:bg-accent/50 transition-colors" onClick={onToggle}>
        {isExpanded ? <ChevronDown className="h-4 w-4 flex-shrink-0" /> : <ChevronRight className="h-4 w-4 flex-shrink-0" />}
        <FileText className="h-4 w-4 flex-shrink-0" />
        <span className="font-mono text-sm flex-1 text-left truncate">{filePath}</span>
        {stats && (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-green-600 dark:text-green-400">+{stats.additions}</span>
            <span className="text-red-600 dark:text-red-400">-{stats.deletions}</span>
          </div>
        )}
      </button>
      {isExpanded && children && <div className="border-t">{children}</div>}
    </div>
  )
}
