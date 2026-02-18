/**
 * Key Change Flow Hook
 *
 * Wraps useKeyChangeWarning with automatic trustDevice call on trust.
 * Eliminates the repeated `await trustDevice(item.tofuNewEntry)` pattern
 * across all consumers.
 */

import { trustDevice } from '@/shared/lib/crypto'
import {
  useKeyChangeWarning,
  type KeyChangeWarningItem,
} from './useKeyChangeWarning'

export interface UseKeyChangeFlowOptions {
  /** Called after trustDevice completes for the trusted item */
  afterTrust?: (item: KeyChangeWarningItem) => void | Promise<void>
  onBlock?: (item: KeyChangeWarningItem) => void | Promise<void>
  onCancel?: (remaining: KeyChangeWarningItem[]) => void | Promise<void>
  /** Called when the queue becomes empty after a trust action */
  onQueueEmpty?: () => void | Promise<void>
}

/**
 * Like useKeyChangeWarning, but automatically calls `trustDevice(item.tofuNewEntry)`
 * before invoking the caller's `afterTrust` callback.
 *
 * The `afterTrust` callback always receives the latest closure values
 * because useKeyChangeWarning stores options via an internal ref
 * that is updated every render.
 */
export function useKeyChangeFlow(options: UseKeyChangeFlowOptions = {}) {
  return useKeyChangeWarning({
    onTrust: async (item) => {
      await trustDevice(item.tofuNewEntry)
      await options.afterTrust?.(item)
    },
    onBlock: options.onBlock,
    onCancel: options.onCancel,
    onQueueEmpty: options.onQueueEmpty,
  })
}
