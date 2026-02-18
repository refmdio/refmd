/**
 * Pending Device Monitor
 *
 * Uses SSE (Server-Sent Events) to receive pending device notifications in real-time.
 * Auto-shows approval dialog when a new device requests approval.
 */

import type { ReactNode } from 'react'
import {
  PendingDeviceContext,
  usePendingDeviceModel,
} from '../model/usePendingDevices'
import { PendingDeviceDialog } from './PendingDeviceDialog'

interface PendingDeviceProviderProps {
  children: ReactNode
}

export function PendingDeviceProvider({ children }: PendingDeviceProviderProps) {
  const { contextValue, currentDialog, handleDialogClose, handleApproved } = usePendingDeviceModel()

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
