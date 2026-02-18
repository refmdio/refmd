import { describe, it, expect, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useAsyncData } from './useAsyncData'

describe('useAsyncData', () => {
  it('fetches data when all deps are present', async () => {
    const fetcher = vi.fn().mockResolvedValue('result')

    const { result } = renderHook(() => useAsyncData(fetcher, ['dep1', 'dep2']))

    expect(result.current.isLoading).toBe(true)
    expect(result.current.data).toBe(null)

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.data).toBe('result')
    expect(result.current.error).toBe(null)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('skips fetch when a dep is null', () => {
    const fetcher = vi.fn().mockResolvedValue('result')

    const { result } = renderHook(() => useAsyncData(fetcher, ['dep1', null]))

    expect(result.current.isLoading).toBe(false)
    expect(result.current.data).toBe(null)
    expect(result.current.error).toBe(null)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('skips fetch when a dep is undefined', () => {
    const fetcher = vi.fn().mockResolvedValue('result')

    const { result } = renderHook(() => useAsyncData(fetcher, [undefined]))

    expect(fetcher).not.toHaveBeenCalled()
    expect(result.current.isLoading).toBe(false)
  })

  it('sets error when fetcher rejects', async () => {
    const fetcher = vi.fn().mockRejectedValue(new Error('fetch failed'))

    const { result } = renderHook(() => useAsyncData(fetcher, ['dep']))

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.data).toBe(null)
    expect(result.current.error).toBeInstanceOf(Error)
    expect(result.current.error!.message).toBe('fetch failed')
  })

  it('wraps non-Error rejections', async () => {
    const fetcher = vi.fn().mockRejectedValue('string error')

    const { result } = renderHook(() => useAsyncData(fetcher, ['dep']))

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.error).toBeInstanceOf(Error)
    expect(result.current.error!.message).toBe('string error')
  })

  it('re-fetches when deps change', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce('first')
      .mockResolvedValueOnce('second')

    const { result, rerender } = renderHook(
      ({ dep }) => useAsyncData(fetcher, [dep]),
      { initialProps: { dep: 'a' } },
    )

    await waitFor(() => {
      expect(result.current.data).toBe('first')
    })

    rerender({ dep: 'b' })

    await waitFor(() => {
      expect(result.current.data).toBe('second')
    })

    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('resets data when deps become null', async () => {
    const fetcher = vi.fn().mockResolvedValue('result')

    const { result, rerender } = renderHook(
      ({ dep }) => useAsyncData(fetcher, [dep]),
      { initialProps: { dep: 'a' as string | null } },
    )

    await waitFor(() => {
      expect(result.current.data).toBe('result')
    })

    rerender({ dep: null })

    expect(result.current.data).toBe(null)
    expect(result.current.isLoading).toBe(false)
    expect(result.current.error).toBe(null)
  })

  it('cancels in-flight fetch on dep change', async () => {
    let resolveFirst: (v: string) => void
    const firstPromise = new Promise<string>((r) => { resolveFirst = r })
    const fetcher = vi.fn()
      .mockReturnValueOnce(firstPromise)
      .mockResolvedValueOnce('second')

    const { result, rerender } = renderHook(
      ({ dep }) => useAsyncData(fetcher, [dep]),
      { initialProps: { dep: 'a' } },
    )

    // Change dep before first resolves
    rerender({ dep: 'b' })

    await waitFor(() => {
      expect(result.current.data).toBe('second')
    })

    // Resolve the stale first fetch — should not overwrite
    resolveFirst!('first')
    // Give it a tick
    await new Promise((r) => setTimeout(r, 10))

    expect(result.current.data).toBe('second')
  })
})
