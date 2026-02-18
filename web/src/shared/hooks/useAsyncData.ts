import { useState, useEffect, useRef } from 'react'

interface UseAsyncDataResult<T> {
  data: T | null
  isLoading: boolean
  error: Error | null
}

/**
 * Hook for async data fetching with automatic cancellation on unmount/dep change.
 * Replaces the `useEffect + cancelled` flag pattern.
 *
 * Returns `{ data: null, isLoading: false, error: null }` when deps contain falsy values
 * (i.e. the fetcher is not called).
 *
 * @param fetcher Async function returning data. Called when all deps are truthy.
 * @param deps Dependency array — fetcher is re-called when these change.
 *             If any dep is null/undefined, the fetcher is skipped and data is reset.
 */
export function useAsyncData<T>(
  fetcher: () => Promise<T>,
  deps: readonly unknown[],
): UseAsyncDataResult<T> {
  const [data, setData] = useState<T | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const hasMissingDeps = deps.some(d => d == null)
  const depsKey = JSON.stringify(deps)

  useEffect(() => {
    if (hasMissingDeps) {
      setData(null)
      setError(null)
      setIsLoading(false)
      return
    }

    let cancelled = false

    setIsLoading(true)
    setError(null)

    fetcherRef.current()
      .then((result) => {
        if (!cancelled) setData(result)
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)))
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [depsKey, hasMissingDeps])

  return { data, isLoading, error }
}
