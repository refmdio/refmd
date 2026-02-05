/**
 * Key Change Warning Dialog
 *
 * Displayed when TOFU verification detects that a device's signing key
 * has changed. This could indicate:
 * - The user legitimately re-registered the device
 * - A potential man-in-the-middle attack
 *
 * The user must explicitly choose to trust the new key or block the device.
 */

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { Button } from '@/shared/ui/button'
import { AlertTriangle, Shield, ShieldOff } from 'lucide-react'

interface KeyChangeWarningDialogProps {
  /** Whether the dialog is open */
  open: boolean
  /** Device name */
  deviceName: string
  /** Old fingerprint (formatted with spaces) */
  oldFingerprint: string
  /** New fingerprint (formatted with spaces) */
  newFingerprint: string
  /** Called when user chooses to trust the new key */
  onTrust: () => void
  /** Called when user chooses to block the device */
  onBlock: () => void
  /** Called when dialog is dismissed without action */
  onCancel: () => void
}

export function KeyChangeWarningDialog({
  open,
  deviceName,
  oldFingerprint,
  newFingerprint,
  onTrust,
  onBlock,
  onCancel,
}: KeyChangeWarningDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && onCancel()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <div className="flex items-center gap-3 mb-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900">
              <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400" />
            </div>
            <DialogTitle className="text-lg">Security Key Changed</DialogTitle>
          </div>
          <DialogDescription>
            The security key for device &quot;{deviceName}&quot; has changed since you last
            verified it. This can happen when:
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
            <li>The device was re-registered with new keys</li>
            <li>The device data was reset or cleared</li>
            <li>Someone is attempting to impersonate this device</li>
          </ul>

          <div className="rounded-lg border bg-muted/50 p-4 space-y-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Previous fingerprint</div>
              <code className="block text-sm font-mono bg-background p-2 rounded border text-red-600 dark:text-red-400 break-all">
                {oldFingerprint}
              </code>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">New fingerprint</div>
              <code className="block text-sm font-mono bg-background p-2 rounded border text-green-600 dark:text-green-400 break-all">
                {newFingerprint}
              </code>
            </div>
          </div>

          <div className="p-3 text-sm bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-lg">
            <strong className="text-amber-800 dark:text-amber-200">
              If you did not expect this change:
            </strong>
            <p className="text-amber-700 dark:text-amber-300 mt-1">
              Block this device and verify the device owner through a secure channel
              before trusting the new key.
            </p>
          </div>
        </div>

        <DialogFooter className="flex-col gap-2 sm:flex-row">
          <Button
            variant="outline"
            className="w-full sm:w-auto"
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            className="w-full sm:w-auto"
            onClick={onBlock}
          >
            <ShieldOff className="mr-2 h-4 w-4" />
            Block Device
          </Button>
          <Button
            variant="default"
            className="w-full sm:w-auto"
            onClick={onTrust}
          >
            <Shield className="mr-2 h-4 w-4" />
            Trust New Key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
