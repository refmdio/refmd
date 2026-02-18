import { useState, useCallback, useRef, useEffect } from 'react'
import type { KeyChangeWarningItem, KeyChangeWarningDialogProps } from '@/shared/model/key-change-types'
import { logger } from '@/shared/lib/logger'

export type { KeyChangeWarningItem, KeyChangeWarningDialogProps } from '@/shared/model/key-change-types'

export interface UseKeyChangeWarningOptions {
  onTrust?: (item: KeyChangeWarningItem) => void | Promise<void>
  onBlock?: (item: KeyChangeWarningItem) => void | Promise<void>
  onCancel?: (remaining: KeyChangeWarningItem[]) => void | Promise<void>
  /** Called when the queue becomes empty after a trust action */
  onQueueEmpty?: () => void | Promise<void>
}

export function useKeyChangeWarning(options: UseKeyChangeWarningOptions = {}) {
  const [queue, setQueue] = useState<KeyChangeWarningItem[]>([])
  const optionsRef = useRef(options)
  optionsRef.current = options
  const wasNonEmptyRef = useRef(false)

  const current = queue[0] ?? null

  // Track queue empty transitions via useEffect to avoid race conditions.
  // The previous approach checked queue.length before awaiting the callback,
  // so items pushed during the callback would not prevent onQueueEmpty from firing.
  useEffect(() => {
    if (queue.length > 0) {
      wasNonEmptyRef.current = true
    } else if (wasNonEmptyRef.current) {
      wasNonEmptyRef.current = false
      Promise.resolve(optionsRef.current.onQueueEmpty?.()).catch((err) => {
        logger.error('key-change', 'onQueueEmpty callback failed', err)
      })
    }
  }, [queue.length])

  const push = useCallback((...items: KeyChangeWarningItem[]) => {
    setQueue((prev) => [...prev, ...items])
  }, [])

  const set = useCallback((items: KeyChangeWarningItem[]) => {
    setQueue(items)
  }, [])

  const advanceQueue = useCallback(
    async (callback: ((item: KeyChangeWarningItem) => void | Promise<void>) | undefined) => {
      if (!current) return
      const item = current
      setQueue((prev) => prev.slice(1))
      await callback?.(item)
    },
    [current],
  )

  const handleTrust = useCallback(
    () => advanceQueue(optionsRef.current.onTrust),
    [advanceQueue],
  )

  const handleBlock = useCallback(
    () => advanceQueue(optionsRef.current.onBlock),
    [advanceQueue],
  )

  const handleCancel = useCallback(async () => {
    const remaining = [...queue]
    setQueue([])
    await optionsRef.current.onCancel?.(remaining)
  }, [queue])

  const dialogProps: KeyChangeWarningDialogProps | null = current
    ? {
        open: true,
        deviceName: current.displayName,
        oldFingerprint: current.oldFingerprint,
        newFingerprint: current.newFingerprint,
        onTrust: handleTrust,
        onBlock: handleBlock,
        onCancel: handleCancel,
      }
    : null

  return {
    current,
    queue,
    push,
    set,
    handleTrust,
    handleBlock,
    handleCancel,
    dialogProps,
  }
}
