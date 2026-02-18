import { useRef } from 'react'

/**
 * Returns a ref that always holds the latest value.
 * Eliminates the stale closure pattern of manual useRef + assignment.
 */
export function useLatest<T>(value: T): { readonly current: T } {
  const ref = useRef(value)
  ref.current = value
  return ref
}
