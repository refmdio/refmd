import { Loader2, WifiOff, RefreshCw } from 'lucide-react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'

import { useNetworkStatus } from '../hooks/useNetworkStatus'
import { useOfflineQueue } from '../hooks/useOfflineQueue'

interface OfflineBannerProps {
  /** Additional class names */
  className?: string
  /** Whether to show pending operations count */
  showPendingCount?: boolean
  /** Handler to process operations (passed to useOfflineQueue) */
  processOperation?: (operation: unknown) => Promise<void>
}

/**
 * Banner that shows offline status and pending operations
 *
 * @example
 * ```tsx
 * // In your layout
 * <OfflineBanner />
 * ```
 */
export function OfflineBanner({
  className,
  showPendingCount = true,
  processOperation,
}: OfflineBannerProps) {
  const { isOnline } = useNetworkStatus()
  const { pendingCount, processing, processQueue } = useOfflineQueue({
    processOperation: processOperation as (op: { payload: string }) => Promise<void>,
    autoProcess: true,
  })

  // Don't show if online and no pending operations
  if (isOnline && pendingCount === 0) {
    return null
  }

  return (
    <div
      className={cn(
        'fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-4 py-2 text-sm',
        !isOnline
          ? 'bg-amber-500 text-white'
          : 'bg-blue-500 text-white',
        className
      )}
    >
      <div className="flex items-center gap-2">
        {!isOnline ? (
          <>
            <WifiOff className="h-4 w-4" />
            <span>
              You are offline.
              {showPendingCount && pendingCount > 0 && (
                <span className="ml-1">
                  {pendingCount} {pendingCount === 1 ? 'change' : 'changes'} will sync when you reconnect.
                </span>
              )}
            </span>
          </>
        ) : processing ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>
              Syncing {pendingCount} {pendingCount === 1 ? 'change' : 'changes'}...
            </span>
          </>
        ) : (
          <>
            <RefreshCw className="h-4 w-4" />
            <span>
              {pendingCount} pending {pendingCount === 1 ? 'change' : 'changes'}
            </span>
          </>
        )}
      </div>

      {isOnline && !processing && pendingCount > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className="text-white hover:bg-white/20"
          onClick={processQueue}
        >
          <RefreshCw className="mr-2 h-3 w-3" />
          Sync now
        </Button>
      )}
    </div>
  )
}
