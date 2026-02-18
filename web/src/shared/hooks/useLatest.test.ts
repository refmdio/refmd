import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useLatest } from './useLatest'

describe('useLatest', () => {
  it('returns initial value', () => {
    const { result } = renderHook(() => useLatest(42))
    expect(result.current.current).toBe(42)
  })

  it('updates ref on re-render', () => {
    const { result, rerender } = renderHook(({ value }) => useLatest(value), {
      initialProps: { value: 'a' },
    })
    expect(result.current.current).toBe('a')

    rerender({ value: 'b' })
    expect(result.current.current).toBe('b')
  })
})
