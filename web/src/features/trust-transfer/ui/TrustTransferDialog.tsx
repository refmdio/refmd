/**
 * Trust Transfer Dialog
 *
 * Shown after device registration to offer transferring trust state
 * from an existing device. This includes TOFU entries for known devices.
 */

import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { Button } from '@/shared/ui/button'
import { CheckCircle, Laptop, Loader2, Shield, XCircle } from 'lucide-react'

type TransferStep = 'prompt' | 'waiting' | 'transferring' | 'success' | 'error'

interface TrustTransferDialogProps {
  /** Whether the dialog is open */
  open: boolean
  /** Number of existing devices available for transfer */
  existingDeviceCount: number
  /** Called when user wants to transfer from existing device */
  onTransfer: () => Promise<void>
  /** Called when user skips the transfer */
  onSkip: () => void
  /** Called when dialog is closed after completion */
  onClose: () => void
}

export function TrustTransferDialog({
  open,
  existingDeviceCount,
  onTransfer,
  onSkip,
  onClose,
}: TrustTransferDialogProps) {
  const [step, setStep] = useState<TransferStep>('prompt')
  const [error, setError] = useState<string | null>(null)

  const handleTransfer = async () => {
    try {
      setStep('waiting')
      setError(null)
      await onTransfer()
      setStep('success')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Transfer failed')
      setStep('error')
    }
  }

  const handleRetry = () => {
    setStep('prompt')
    setError(null)
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && (step === 'success' ? onClose() : onSkip())}>
      <DialogContent className="sm:max-w-md">
        {step === 'prompt' && (
          <>
            <DialogHeader>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                  <Shield className="h-5 w-5 text-primary" />
                </div>
                <DialogTitle>Transfer Trust State</DialogTitle>
              </div>
              <DialogDescription>
                You have {existingDeviceCount} existing device{existingDeviceCount !== 1 ? 's' : ''}.
                Would you like to transfer your trust state from an existing device?
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 py-4">
              <div className="rounded-lg border bg-muted/50 p-4 space-y-2 text-sm">
                <p className="font-medium">Trust state includes:</p>
                <ul className="list-disc list-inside text-muted-foreground space-y-1">
                  <li>Verified device fingerprints</li>
                  <li>Trust history for known devices</li>
                </ul>
              </div>

              <p className="text-sm text-muted-foreground">
                Without transferring, you&apos;ll need to manually verify each device
                when communicating with them.
              </p>
            </div>

            <DialogFooter className="flex-col gap-2 sm:flex-row">
              <Button
                variant="outline"
                className="w-full sm:w-auto"
                onClick={onSkip}
              >
                Skip
              </Button>
              <Button
                className="w-full sm:w-auto"
                onClick={handleTransfer}
              >
                <Laptop className="mr-2 h-4 w-4" />
                Transfer from Device
              </Button>
            </DialogFooter>
          </>
        )}

        {step === 'waiting' && (
          <>
            <DialogHeader>
              <DialogTitle>Waiting for Approval</DialogTitle>
              <DialogDescription>
                Approve the transfer request on your existing device.
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col items-center gap-4 py-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <p className="text-sm text-muted-foreground text-center">
                A notification has been sent to your other device(s).
                Please approve the transfer to continue.
              </p>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={onSkip}>
                Cancel
              </Button>
            </DialogFooter>
          </>
        )}

        {step === 'transferring' && (
          <>
            <DialogHeader>
              <DialogTitle>Transferring</DialogTitle>
              <DialogDescription>
                Securely transferring your trust state...
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col items-center gap-4 py-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <p className="text-sm text-muted-foreground">
                Encrypting and verifying trust data...
              </p>
            </div>
          </>
        )}

        {step === 'success' && (
          <>
            <DialogHeader>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                </div>
                <DialogTitle>Transfer Complete</DialogTitle>
              </div>
              <DialogDescription>
                Your trust state has been successfully transferred to this device.
              </DialogDescription>
            </DialogHeader>

            <div className="py-4">
              <p className="text-sm text-muted-foreground">
                All verified device fingerprints are now available on this device.
                You won&apos;t need to manually verify previously trusted devices.
              </p>
            </div>

            <DialogFooter>
              <Button onClick={onClose}>Continue</Button>
            </DialogFooter>
          </>
        )}

        {step === 'error' && (
          <>
            <DialogHeader>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/10">
                  <XCircle className="h-5 w-5 text-destructive" />
                </div>
                <DialogTitle>Transfer Failed</DialogTitle>
              </div>
              <DialogDescription>
                Unable to complete the trust state transfer.
              </DialogDescription>
            </DialogHeader>

            <div className="py-4">
              <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                {error}
              </div>
            </div>

            <DialogFooter className="flex-col gap-2 sm:flex-row">
              <Button variant="outline" onClick={onSkip}>
                Skip
              </Button>
              <Button onClick={handleRetry}>
                Try Again
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
