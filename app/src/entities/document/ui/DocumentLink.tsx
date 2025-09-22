import { Link } from '@tanstack/react-router'
import { FileText, Folder, NotebookText } from 'lucide-react'

import { cn } from '@/shared/lib/utils'

export function DocumentLink({ id, type, title, className }: { id: string; type?: string; title?: string; className?: string }) {
  const to = `/document/${id}`
  const t = String(type || 'document').toLowerCase()
  const Icon = t === 'folder' ? Folder : t === 'scrap' ? NotebookText : FileText
  return (
    <Link to={to as any} className={cn('inline-flex items-center gap-1 hover:underline', className)}>
      <Icon className="h-4 w-4 text-muted-foreground" />
      <span className="truncate max-w-[240px]">{title || 'Untitled'}</span>
    </Link>
  )
}

export default DocumentLink
