const sizeClasses = {
  sm: 'h-4 w-4',
  md: 'h-8 w-8',
  lg: 'h-12 w-12',
} as const

interface SpinnerProps {
  size?: keyof typeof sizeClasses
  className?: string
}

export function Spinner({ size = 'md', className }: SpinnerProps) {
  return (
    <div
      className={`animate-spin rounded-full border-b-2 border-primary ${sizeClasses[size]} ${className ?? ''}`}
      role="status"
      aria-label="Loading"
    />
  )
}
