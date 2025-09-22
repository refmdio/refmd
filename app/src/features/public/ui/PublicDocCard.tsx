// no react import needed with automatic JSX runtime
import { ArrowUpRight, Calendar, FileText } from 'lucide-react'

import { Card, CardContent, CardHeader, CardTitle } from '@/shared/ui/card'
import { Separator } from '@/shared/ui/separator'

type Props = {
  href: string
  title: string
  publishedAt: string
  updatedAt?: string
}

export default function PublicDocCard({ href, title, publishedAt, updatedAt }: Props) {
  const showUpdated = !!updatedAt && updatedAt !== publishedAt
  const formatDate = (value: string) => {
    try {
      return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(value))
    } catch {
      return value
    }
  }
  return (
    <Card className="group relative overflow-hidden border-border/70 bg-card/90 transition-all duration-200 hover:-translate-y-1 hover:border-primary/40 hover:shadow-2xl">
      <a href={href} className="flex h-full flex-col no-underline">
        <CardHeader className="relative space-y-4">
          <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <span className="inline-flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Document
            </span>
            <ArrowUpRight className="h-4 w-4 transition-transform duration-200 group-hover:-translate-y-1 group-hover:translate-x-1" />
          </div>
          <CardTitle className="text-xl font-semibold leading-tight text-foreground transition-colors group-hover:text-primary">
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent className="mt-auto space-y-3 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <Calendar className="h-4 w-4" />
            <span>Published {formatDate(publishedAt)}</span>
          </div>
          {showUpdated && (
            <>
              <Separator className="border-dashed" />
              <div>Updated {formatDate(updatedAt!)}</div>
            </>
          )}
        </CardContent>
      </a>
    </Card>
  )
}
