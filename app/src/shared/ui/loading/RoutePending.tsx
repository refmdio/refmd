export default function RoutePending({ label = 'Loading…' }: { label?: string }) {
  return <div className="p-6 text-sm text-muted-foreground">{label}</div>
}
