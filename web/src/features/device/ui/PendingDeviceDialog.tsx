/**
 * Pending Device Approval Dialog
 *
 * Automatically shown when a new device registration request is detected.
 * Allows existing device to approve via SAS verification.
 */

import { useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { Button } from '@/shared/ui/button'
import { Spinner } from '@/shared/ui/spinner'
import { SasVerification } from './SasVerification'
import { type PendingDevice } from '@/shared/api'
import { useAuthContext } from '@/shared/context'
import { KeyChangeGuard } from '@/shared/ui/KeyChangeGuard'
import { ErrorAlert } from '@/shared/ui/error-alert'
import { useDeviceApprovalFlow } from '../model/useDeviceApprovalFlow'

interface PendingDeviceDialogProps {
  device: PendingDevice
  onClose: () => void
  onApproved: () => void
}

export function PendingDeviceDialog({ device, onClose, onApproved }: PendingDeviceDialogProps) {
  const { auth, device: currentDevice } = useAuthContext()

  const flow = useDeviceApprovalFlow({
    device,
    auth,
    currentDevice,
    onApproved,
    onClose,
  })

  // Load SAS on mount with cancellation support
  useEffect(() => {
    flow.cancelledRef.current = false
    flow.loadSas()

    return () => {
      flow.cancelledRef.current = true
    }
  }, [flow.loadSas])

  return (
    <KeyChangeGuard dialogProps={flow.keyChangeDialogProps}>
      <Dialog open onOpenChange={(open) => !open && onClose()}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>New Device Request</DialogTitle>
            <DialogDescription>
              A new device wants to access your account
            </DialogDescription>
          </DialogHeader>

          {/* Device Info */}
          <div className="rounded-lg border bg-muted/50 p-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Device</span>
              <span className="font-medium">{device.name}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Type</span>
              <span className="font-medium capitalize">{device.device_type}</span>
            </div>
            {device.ip_address && (
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">IP Address</span>
                <span className="font-medium font-mono">{device.ip_address}</span>
              </div>
            )}
          </div>

          <div className="space-y-4">
            {flow.step === 'loading' && (
              <div className="flex justify-center py-8">
                <Spinner />
              </div>
            )}

            {flow.step === 'verify' && flow.sasEmojis && (
              <>
                <SasVerification emojis={flow.sasEmojis} role="existing" />

                <div className="flex gap-3">
                  <Button className="flex-1" onClick={flow.handleApprove}>
                    Approve
                  </Button>
                  <Button variant="destructive" className="flex-1" onClick={flow.handleReject}>
                    Reject
                  </Button>
                </div>
              </>
            )}

            {flow.step === 'approving' && (
              <div className="flex flex-col items-center gap-4 py-8">
                <Spinner />
                <p className="text-sm text-muted-foreground">Approving device…</p>
              </div>
            )}

            {flow.step === 'error' && (
              <div className="space-y-4">
                <ErrorAlert>{flow.error}</ErrorAlert>
                <div className="flex gap-3">
                  <Button variant="outline" className="flex-1" onClick={flow.loadSas}>
                    Retry
                  </Button>
                  <Button variant="ghost" className="flex-1" onClick={onClose}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </KeyChangeGuard>
  )
}
