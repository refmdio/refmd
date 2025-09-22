import { Badge } from '@/shared/ui/badge'

export function DocumentBadge({ type, className }: { type?: string; className?: string }) {
  const t = String(type || 'document').toLowerCase()
  const label = t.toUpperCase()
  return (
    <Badge variant="secondary" className={className}>{label}</Badge>
  )
}

export default DocumentBadge
