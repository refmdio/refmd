import { useEffect, useRef } from 'react'
import { createAuthenticatedEventSource, parseSSEData } from '@/shared/lib/sse'

/**
 * React hook for managing an SSE connection with automatic lifecycle management.
 */
export function useEventSource(options: {
  url: string
  onMessage: (data: unknown) => void
  enabled?: boolean
}) {
  const { url, onMessage, enabled = true } = options
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  useEffect(() => {
    if (!enabled) return

    const eventSource = createAuthenticatedEventSource(url)

    eventSource.onmessage = (event) => {
      const data = parseSSEData(event)
      if (data !== null) onMessageRef.current(data)
    }

    eventSource.onerror = () => {
      // EventSource will automatically reconnect
    }

    return () => {
      eventSource.close()
    }
  }, [url, enabled])
}
