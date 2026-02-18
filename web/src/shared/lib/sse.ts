/**
 * Create an authenticated EventSource with credential forwarding.
 * Centralizes the withCredentials config used by all SSE consumers.
 */
export function createAuthenticatedEventSource(url: string): EventSource {
  return new EventSource(url, { withCredentials: true })
}

/**
 * Parse an SSE MessageEvent's data as JSON.
 * Returns null on parse failure instead of throwing.
 */
export function parseSSEData(event: MessageEvent): unknown | null {
  try {
    return JSON.parse(event.data)
  } catch {
    return null
  }
}

/**
 * One-shot SSE listener that resolves when a matching event is received.
 */
export function waitForSSEEvent<T>(options: {
  url: string
  match: (data: unknown) => T | false
  timeoutMs?: number
}): Promise<T> {
  const { url, match, timeoutMs = 10000 } = options

  return new Promise<T>((resolve, reject) => {
    const eventSource = createAuthenticatedEventSource(url)

    const timeoutId = setTimeout(() => {
      eventSource.close()
      reject(new Error('Timeout waiting for SSE event'))
    }, timeoutMs)

    eventSource.onmessage = (event) => {
      const data = parseSSEData(event)
      if (data === null) return
      const result = match(data)
      if (result !== false) {
        clearTimeout(timeoutId)
        eventSource.close()
        resolve(result)
      }
    }

    eventSource.onerror = () => {
      // Only reject on permanent failure (CLOSED).
      // When readyState is CONNECTING, the browser is auto-reconnecting
      // after a transient error — let the timeout handle the deadline.
      if (eventSource.readyState === EventSource.CLOSED) {
        clearTimeout(timeoutId)
        reject(new Error('SSE connection error'))
      }
    }
  })
}
