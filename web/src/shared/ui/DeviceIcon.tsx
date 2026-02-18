import { Monitor, Smartphone, Globe } from 'lucide-react'

export function DeviceIcon({ type }: { type: string }) {
  switch (type) {
    case 'mobile':
      return <Smartphone className="h-4 w-4" aria-hidden="true" />
    case 'desktop':
      return <Monitor className="h-4 w-4" aria-hidden="true" />
    default:
      return <Globe className="h-4 w-4" aria-hidden="true" />
  }
}
