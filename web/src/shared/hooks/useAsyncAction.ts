import { useState, useCallback } from 'react'

export function useAsyncAction(getErrorMessage?: (err: unknown) => string) {
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const execute = useCallback(async (action: () => Promise<void>): Promise<boolean> => {
    setError(null)
    setLoading(true)
    try {
      await action()
      return true
    } catch (err) {
      setError(getErrorMessage ? getErrorMessage(err) : (err instanceof Error ? err.message : String(err)))
      return false
    } finally {
      setLoading(false)
    }
  }, [getErrorMessage])

  return { error, setError, loading, execute }
}
