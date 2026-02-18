import { cn } from '@/shared/lib/utils'

interface ErrorAlertProps {
  className?: string
  children: React.ReactNode
}

export function ErrorAlert({ className, children }: ErrorAlertProps) {
  return (
    <div className={cn(
      'p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded',
      className
    )}>
      {children}
    </div>
  )
}
