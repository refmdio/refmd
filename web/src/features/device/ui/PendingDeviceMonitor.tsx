/**
 * Pending Device Monitor
 *
 * Uses SSE (Server-Sent Events) to receive pending device notifications in real-time.
 * Auto-shows approval dialog when a new device requests approval.
 */

import { useState, useEffect, useCallback, createContext, useContext, useRef, type ReactNode } from 'react'
import { deviceApi, sseUrls } from '@/shared/api'
import { PendingDeviceDialog } from './PendingDeviceDialog'

interface PendingDevice {
  id: string
  name: string
  device_type: string
  ip_address?: string | null
  created_at: string
  expires_at: string
}

interface DeviceEvent {
  type: 'pending_created' | 'pending_approved' | 'pending_removed'
  pending_id: string
  user_id: string
  device_name?: string
  device_type?: string
  ip_address?: string | null
  expires_at?: string
  device_id?: string
}

interface PendingDeviceContextValue {
  /** List of pending devices */
  pendingDevices: PendingDevice[]
  /** Number of pending devices (for badge) */
  pendingCount: number
  /** Show approval dialog for a specific device */
  showApprovalDialog: (device: PendingDevice) => void
  /** Refresh pending devices list */
  refresh: () => Promise<void>
}

const PendingDeviceContext = createContext<PendingDeviceContextValue | null>(null)

export function usePendingDevices() {
  const context = useContext(PendingDeviceContext)
  if (!context) {
    throw new Error('usePendingDevices must be used within PendingDeviceProvider')
  }
  return context
}

interface PendingDeviceProviderProps {
  children: ReactNode
}

export function PendingDeviceProvider({ children }: PendingDeviceProviderProps) {
  const [pendingDevices, setPendingDevices] = useState<PendingDevice[]>([])
  const [seenDeviceIds, setSeenDeviceIds] = useState<Set<string>>(new Set())
  const [currentDialog, setCurrentDialog] = useState<PendingDevice | null>(null)
  const dismissedRef = useRef<Set<string>>(new Set())
  const eventSourceRef = useRef<EventSource | null>(null)

  // Fetch pending devices (initial load only)
  const fetchPendingDevices = useCallback(async () => {
    try {
      const response = await deviceApi.listPendingDevices()
      setPendingDevices(response.pending_devices)
      return response.pending_devices
    } catch (err) {
      console.error('Failed to fetch pending devices:', err)
      return []
    }
  }, [])

  // Setup SSE connection
  useEffect(() => {
    // Initial fetch
    fetchPendingDevices()

    // Connect to SSE endpoint
    const eventSource = new EventSource(sseUrls.deviceEvents(), {
      withCredentials: true,
    })
    eventSourceRef.current = eventSource

    eventSource.onmessage = (event) => {
      try {
        const data: DeviceEvent = JSON.parse(event.data)

        switch (data.type) {
          case 'pending_created': {
            // Add new pending device (with deduplication)
            const newDevice: PendingDevice = {
              id: data.pending_id,
              name: data.device_name || 'Unknown Device',
              device_type: data.device_type || 'browser',
              ip_address: data.ip_address,
              created_at: new Date().toISOString(),
              expires_at: data.expires_at || new Date(Date.now() + 5 * 60 * 1000).toISOString(),
            }
            setPendingDevices((prev) => {
              // Check if device already exists
              if (prev.some((d) => d.id === data.pending_id)) {
                return prev
              }
              return [...prev, newDevice]
            })

            // Auto-show dialog if not dismissed and no dialog is currently open
            if (!dismissedRef.current.has(data.pending_id)) {
              setSeenDeviceIds((prev) => new Set([...prev, data.pending_id]))
              // Only show if no other dialog is open to avoid overriding
              setCurrentDialog((current) => current ?? newDevice)
            }
            break
          }
          case 'pending_approved':
          case 'pending_removed': {
            // Remove from pending list
            setPendingDevices((prev) => prev.filter((d) => d.id !== data.pending_id))
            // Close dialog if it's for this device
            setCurrentDialog((current) => (current?.id === data.pending_id ? null : current))
            break
          }
        }
      } catch (err) {
        console.error('Failed to parse SSE event:', err)
      }
    }

    eventSource.onerror = (err) => {
      console.error('SSE connection error:', err)
      // EventSource will automatically reconnect
    }

    return () => {
      eventSource.close()
      eventSourceRef.current = null
    }
  }, [fetchPendingDevices])

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
      setSeenDeviceIds((prev) => new Set([...prev, newDevice.id]))
      // Use functional update to avoid overriding a dialog opened by SSE
      setCurrentDialog((current) => current ?? newDevice)
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
    refresh: async () => { await fetchPendingDevices() },
  }

  return (
    <PendingDeviceContext.Provider value={contextValue}>
      {children}
      {currentDialog && (
        <PendingDeviceDialog
          device={currentDialog}
          onClose={handleDialogClose}
          onApproved={handleApproved}
        />
      )}
    </PendingDeviceContext.Provider>
  )
}
