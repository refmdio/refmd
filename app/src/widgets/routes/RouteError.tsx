export default function RouteError({ error }: { error: unknown }) {
  const message = (() => {
    if (!error) return 'Unknown error'
    if (typeof error === 'string') return error
    if (error instanceof Error) return error.message
    try { return JSON.stringify(error) } catch { return String(error) }
  })()
  return <div className="p-6 text-sm text-destructive">{message}</div>
}
