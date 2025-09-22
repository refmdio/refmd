
type Props = {
  label?: string
  className?: string
}

export function EditorOverlay({ label = 'Loading...', className }: Props) {
  return (
    <div className={['absolute inset-0 z-10 flex items-center justify-center bg-background/80 backdrop-blur-sm', className].filter(Boolean).join(' ')}>
      <div className="flex flex-col items-center gap-4">
        <div className="relative">
          <div className="h-10 w-10 rounded-full border-2 border-muted" />
          <div className="absolute inset-0 h-10 w-10 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
        <p className="text-sm text-muted-foreground animate-pulse">{label}</p>
      </div>
    </div>
  )
}

export default EditorOverlay
