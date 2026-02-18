/**
 * Pending Device State Management
 *
 * Manages pending device list, SSE subscriptions, and dialog state.
 * Extracted from ui/PendingDeviceMonitor to follow FSD model/ui separation.
 */

import { useState, useEffect, useCallback, createContext, useContext, useRef } from 'react'
import { deviceApi, sseUrls, routeDeviceSSEEvent, type PendingDevice, type DeviceSSEEvent } from '@/shared/api'
import { useEventSource } from '@/shared/hooks'

export interface PendingDeviceContextValue {
  /** List of pending devices */
  pendingDevices: PendingDevice[]
  /** Number of pending devices (for badge) */
  pendingCount: number
  /** Show approval dialog for a specific device */
  showApprovalDialog: (device: PendingDevice) => void
}

export const PendingDeviceContext = createContext<PendingDeviceContextValue | null>(null)

export function usePendingDevices() {
  const context = useContext(PendingDeviceContext)
  if (!context) {
    throw new Error('usePendingDevices must be used within PendingDeviceProvider')
  }
  return context
}

export interface PendingDeviceModel {
  pendingDevices: PendingDevice[]
  contextValue: PendingDeviceContextValue
  currentDialog: PendingDevice | null
  handleDialogClose: () => void
  handleApproved: () => void
}

export function usePendingDeviceModel(): PendingDeviceModel {
  const [pendingDevices, setPendingDevices] = useState<PendingDevice[]>([])
  const [seenDeviceIds, setSeenDeviceIds] = useState<Set<string>>(new Set())
  const [currentDialog, setCurrentDialog] = useState<PendingDevice | null>(null)
  const dismissedRef = useRef<Set<string>>(new Set())

  // Fetch pending devices (initial load only)
  const fetchPendingDevices = useCallback(async (): Promise<void> => {
    try {
      const response = await deviceApi.listPendingDevices()
      setPendingDevices(response.pending_devices)
    } catch {
      // Silently ignore fetch failures — SSE will keep state updated
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    fetchPendingDevices()
  }, [fetchPendingDevices])

  /** Mark a device as seen and show its dialog if none is currently open */
  const markSeenAndShow = useCallback((device: PendingDevice) => {
    setSeenDeviceIds((prev) => new Set([...prev, device.id]))
    setCurrentDialog((current) => current ?? device)
  }, [])

  const removePending = useCallback((pendingId: string) => {
    setPendingDevices((prev) => prev.filter((d) => d.id !== pendingId))
    setCurrentDialog((current) => (current?.id === pendingId ? null : current))
  }, [])

  const handleSSEMessage = useCallback((data: unknown) => {
    routeDeviceSSEEvent(data as DeviceSSEEvent, {
      onPendingCreated: (event) => {
        const newDevice: PendingDevice = {
          id: event.pending_id,
          name: event.device_name || 'Unknown Device',
          device_type: event.device_type || 'browser',
          ip_address: event.ip_address,
          created_at: new Date().toISOString(),
          expires_at: event.expires_at || new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        }
        setPendingDevices((prev) => {
          if (prev.some((d) => d.id === event.pending_id)) return prev
          return [...prev, newDevice]
        })

        if (!dismissedRef.current.has(event.pending_id)) {
          markSeenAndShow(newDevice)
        }
      },
      onPendingApproved: (event) => removePending(event.pending_id),
      onPendingRemoved: (event) => removePending(event.pending_id),
      onPendingExpired: (event) => removePending(event.pending_id),
    })
  }, [removePending, markSeenAndShow])

  useEventSource({
    url: sseUrls.deviceEvents(),
    onMessage: handleSSEMessage,
  })

  // Auto-show dialog for pending devices on initial load
  useEffect(() => {
    if (pendingDevices.length === 0) {
      return
    }

    // Find device that hasn't been seen or dismissed
    const newDevice = pendingDevices.find(
      (d) => !seenDeviceIds.has(d.id) && !dismissedRef.current.has(d.id)
    )

    if (newDevice) {
      markSeenAndShow(newDevice)
    }
  }, [pendingDevices, seenDeviceIds])

  const showApprovalDialog = useCallback((device: PendingDevice) => {
    setCurrentDialog(device)
  }, [])

  const handleDialogClose = useCallback(() => {
    if (currentDialog) {
      dismissedRef.current.add(currentDialog.id)
    }
    setCurrentDialog(null)
  }, [currentDialog])

  const handleApproved = useCallback(() => {
    setCurrentDialog(null)
    // SSE will automatically update the list
  }, [])

  const contextValue: PendingDeviceContextValue = {
    pendingDevices,
    pendingCount: pendingDevices.length,
    showApprovalDialog,
  }

  return {
    pendingDevices,
    contextValue,
    currentDialog,
    handleDialogClose,
    handleApproved,
  }
}
