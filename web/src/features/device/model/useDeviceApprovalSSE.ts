/**
 * Device Approval SSE Hook
 *
 * Manages SSE connection + polling fallback for monitoring
 * pending device approval status during device registration.
 *
 * Uses shared useEventSource for the SSE connection.
 */

import { useEffect, useRef, useCallback } from 'react'
import { deviceApi, sseUrls, routeDeviceSSEEvent } from '@/shared/api'
import { useEventSource, useLatest } from '@/shared/hooks'

interface UseDeviceApprovalSSEOptions {
  pendingDeviceId: string | null
  enabled: boolean
  onApproved: (deviceId: string) => Promise<void>
  onRejected: () => void
  onExpired: () => void
  /** Called on 404 to disambiguate approval vs rejection. Returns device_id if approved, null if rejected. */
  verifyApproval?: () => Promise<string | null>
}

/**
 * Handle a single poll cycle for pending device status.
 * Returns true if the poll resolved to a terminal state.
 */
async function pollPendingDevice(
  pendingDeviceId: string,
  isHandled: () => boolean,
  markHandled: () => void,
  callbacks: {
    onApproved: (deviceId: string) => Promise<void>
    onRejected: () => void
    onExpired: () => void
    verifyApproval?: () => Promise<string | null>
  },
): Promise<boolean> {
  if (isHandled()) return true

  try {
    await deviceApi.getSas(pendingDeviceId)
    return false
  } catch (err) {
    if (!err || typeof err !== 'object' || !('status' in err)) return false
    const status = (err as { status: number }).status

    if (status === 410) {
      markHandled()
      callbacks.onExpired()
      return true
    }

    if (status === 404) {
      // 404 is ambiguous: pending device deleted on both approval and rejection.
      // Wait briefly to let SSE catch up before disambiguating.
      await new Promise(r => setTimeout(r, 2000))
      if (isHandled()) return true

      if (callbacks.verifyApproval) {
        try {
          const approvedDeviceId = await callbacks.verifyApproval()
          if (isHandled()) return true

          if (approvedDeviceId) {
            markHandled()
            await callbacks.onApproved(approvedDeviceId)
            return true
          }
        } catch {
          // Verification failed — fall through to rejection
        }
      }

      markHandled()
      callbacks.onRejected()
      return true
    }

    return false
  }
}

export function useDeviceApprovalSSE({
  pendingDeviceId,
  enabled,
  onApproved,
  onRejected,
  onExpired,
  verifyApproval,
}: UseDeviceApprovalSSEOptions) {
  const onApprovedRef = useLatest(onApproved)
  const onRejectedRef = useLatest(onRejected)
  const onExpiredRef = useLatest(onExpired)
  const verifyApprovalRef = useLatest(verifyApproval)

  const isHandledRef = useRef(false)

  // Reset handled flag when inputs change
  useEffect(() => {
    isHandledRef.current = false
  }, [enabled, pendingDeviceId])

  const handleMessage = useCallback((data: unknown) => {
    if (isHandledRef.current || !pendingDeviceId) return

    routeDeviceSSEEvent(data as import('@/shared/api').DeviceSSEEvent, {
      onPendingApproved: (event) => {
        if (event.pending_id !== pendingDeviceId) return
        if (event.device_id) {
          isHandledRef.current = true
          onApprovedRef.current(event.device_id).catch(() => {
            isHandledRef.current = false
          })
        }
      },
      onPendingRemoved: (event) => {
        if (event.pending_id !== pendingDeviceId) return
        isHandledRef.current = true
        onRejectedRef.current()
      },
      onPendingExpired: (event) => {
        if (event.pending_id !== pendingDeviceId) return
        isHandledRef.current = true
        onExpiredRef.current()
      },
    })
  }, [pendingDeviceId])

  // SSE connection via shared hook
  useEventSource({
    url: pendingDeviceId ? sseUrls.pendingDeviceEvents(pendingDeviceId) : '',
    onMessage: handleMessage,
    enabled: enabled && !!pendingDeviceId,
  })

  // Polling fallback: check every 5 seconds if pending device still exists.
  // Uses setTimeout chain (not setInterval) to prevent overlapping async polls.
  useEffect(() => {
    if (!enabled || !pendingDeviceId) return

    let cancelled = false
    let activeTimer: ReturnType<typeof setTimeout> | null = null

    async function schedulePoll() {
      if (cancelled) return
      const resolved = await pollPendingDevice(
        pendingDeviceId!,
        () => isHandledRef.current,
        () => { isHandledRef.current = true },
        {
          onApproved: (id) => onApprovedRef.current(id),
          onRejected: () => onRejectedRef.current(),
          onExpired: () => onExpiredRef.current(),
          verifyApproval: verifyApprovalRef.current,
        },
      )
      if (!resolved && !cancelled) {
        activeTimer = setTimeout(schedulePoll, 5000)
      }
    }

    activeTimer = setTimeout(schedulePoll, 5000)

    return () => {
      cancelled = true
      if (activeTimer !== null) clearTimeout(activeTimer)
    }
  }, [enabled, pendingDeviceId])
}
