import { useState, useCallback } from 'react'

export function useAsyncAction(getErrorMessage?: (err: unknown) => string) {
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const execute = useCallback(async (action: () => Promise<void>) => {
    setError(null)
    setLoading(true)
    try {
      await action()
    } catch (err) {
      setError(getErrorMessage ? getErrorMessage(err) : (err instanceof Error ? err.message : String(err)))
    } finally {
      setLoading(false)
    }
  }, [getErrorMessage])

  return { error, setError, loading, execute }
}
