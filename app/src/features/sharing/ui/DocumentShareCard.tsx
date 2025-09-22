// no react import needed with automatic JSX runtime
import { Link } from '@tanstack/react-router'
import { Copy, Trash2, Link as LinkIcon, FileText } from 'lucide-react'

import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'


type Props = {
  id: string
  documentTitle: string
  permission: string
  url: string
  localUrl: string
  expiresAt?: string
  fromFolder?: boolean
  onCopy: (text: string) => void
  onRemove: (token: string) => void
  token: string
}

export default function DocumentShareCard({
  documentTitle,
  permission,
  url,
  localUrl,
  expiresAt,
  fromFolder,
  onCopy,
  onRemove,
  token,
}: Props) {
  const formatDate = (value?: string) => {
    if (!value) return 'No expiry'
    try {
      return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(value))
    } catch {
      return value
    }
  }

  const expiryText = expiresAt ? `Expires ${formatDate(expiresAt)}` : 'No expiry'

  return (
    <Card className="group flex h-full flex-col gap-4 border-border/70 p-5 shadow-sm transition-all duration-200 hover:-translate-y-1 hover:border-primary/40">
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <span className="flex items-center gap-2 text-sm font-medium text-foreground">
            <FileText className="h-4 w-4 text-primary" />
            <span className="truncate">{documentTitle}</span>
          </span>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge variant="outline">{permission}</Badge>
            <Badge variant="secondary">Document</Badge>
            {fromFolder && <Badge variant="secondary">From folder</Badge>}
            <span>{expiryText}</span>
          </div>
        </div>
        <div className="flex flex-col gap-2 text-xs text-muted-foreground">
          <div className="break-all">
            <LinkIcon className="mr-1 inline h-3 w-3" />
            {url}
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button size="sm" variant="outline" asChild className="rounded-full px-4">
            <Link to={localUrl as any}>Open</Link>
          </Button>
          <Button size="sm" variant="outline" className="rounded-full px-3" onClick={() => onCopy(url)}>
            <Copy className="h-4 w-4" />
            <span className="ml-1 text-xs">Copy</span>
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
            onClick={() => onRemove(token)}
          >
            <Trash2 className="h-4 w-4" />
            <span className="ml-1 text-xs">Remove</span>
          </Button>
        </div>
      </div>
    </Card>
  )
}
