import { cn } from '@/shared/lib/utils'

interface LoadingPlaceholderProps {
  className?: string
  children?: React.ReactNode
}

export function LoadingPlaceholder({ className, children }: LoadingPlaceholderProps) {
  return (
    <div className={cn('flex items-center justify-center py-12', className)}>
      <div className="text-muted-foreground">{children ?? 'Loading...'}</div>
    </div>
  )
}
