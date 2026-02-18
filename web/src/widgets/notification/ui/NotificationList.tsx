/**
 * Notification List Component
 *
 * Displays a list of notifications in a popover.
 * Currently supports pending device notifications.
 * Extensible for future notification types.
 */

import { Bell } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/shared/ui/popover'
import { usePendingDevices } from '@/features/device'
import { PendingDeviceInfo } from '@/shared/ui/PendingDeviceInfo'
import type { PendingDevice } from '@/shared/api'

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  return `${Math.floor(diffHours / 24)}d ago`
}

export function NotificationList() {
  const { pendingDevices, pendingCount, showApprovalDialog } = usePendingDevices()

  const totalCount = pendingCount

  const handleDeviceClick = (device: PendingDevice) => {
    showApprovalDialog(device)
  }

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 relative"
          aria-label="Notifications"
        >
          <Bell className="h-4 w-4" aria-hidden="true" />
          {totalCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 bg-yellow-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
              {totalCount > 9 ? '9+' : totalCount}
            </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <div className="px-4 py-3 border-b border-border/60">
          <h4 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Notifications
          </h4>
        </div>

        <div className="max-h-80 overflow-y-auto">
          {totalCount === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No notifications
            </div>
          ) : (
            <div className="divide-y divide-border/40">
              {/* Pending Device Notifications */}
              {pendingDevices.map((device) => (
                <button
                  key={device.id}
                  onClick={() => handleDeviceClick(device)}
                  className="w-full px-4 py-3 text-left hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <PendingDeviceInfo
                      device={device}
                      subtitle={
                        <p className="text-xs text-muted-foreground truncate">
                          New device request
                        </p>
                      }
                    />
                    <span className="text-xs text-muted-foreground whitespace-nowrap ml-auto flex-shrink-0">
                      {formatTimeAgo(device.created_at)}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}
