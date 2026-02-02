export function ErrorDisplay({ message }: { message: string }) {
  return (
    <div className="p-4 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
      {message}
    </div>
  )
}
