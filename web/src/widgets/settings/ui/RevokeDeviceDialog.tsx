import { useState } from 'react'
import { Button } from '@/shared/ui/button'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/shared/ui/dialog'
import type { RevocationMode } from '@/features/device'

interface RevokeDeviceDialogProps {
  deviceName: string | null
  open: boolean
  onClose: () => void
  onConfirm: (mode: RevocationMode) => void
}

export function RevokeDeviceDialog({ deviceName, open, onClose, onConfirm }: RevokeDeviceDialogProps) {
  const [mode, setMode] = useState<RevocationMode>('security')

  const handleClose = () => {
    setMode('security')
    onClose()
  }

  const handleConfirm = () => {
    const selected = mode
    setMode('security')
    onConfirm(selected)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) handleClose() }}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Remove Device</DialogTitle>
          <DialogDescription>
            Remove{' '}
            <span className="font-medium text-foreground">{deviceName ?? 'this device'}</span>.
            {' '}Choose the situation that applies:
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <label
            className={`flex items-start gap-3 rounded-md border p-3 cursor-pointer transition-colors ${
              mode === 'security'
                ? 'border-primary bg-primary/5'
                : 'border-border hover:border-muted-foreground/50'
            }`}
          >
            <input
              type="radio"
              name="revocation-mode"
              value="security"
              checked={mode === 'security'}
              onChange={() => setMode('security')}
              className="mt-1"
            />
            <div className="space-y-1">
              <p className="text-sm font-medium">
                This device was lost, or may have been compromised
              </p>
              <p className="text-xs text-muted-foreground">
                All workspace keys will be regenerated. Active invitation links will be invalidated.
              </p>
            </div>
          </label>

          <label
            className={`flex items-start gap-3 rounded-md border p-3 cursor-pointer transition-colors ${
              mode === 'retire'
                ? 'border-primary bg-primary/5'
                : 'border-border hover:border-muted-foreground/50'
            }`}
          >
            <input
              type="radio"
              name="revocation-mode"
              value="retire"
              checked={mode === 'retire'}
              onChange={() => setMode('retire')}
              className="mt-1"
            />
            <div className="space-y-1">
              <p className="text-sm font-medium">
                This device is in my possession and will be safely wiped
              </p>
              <p className="text-xs text-muted-foreground">
                No key regeneration needed.
              </p>
            </div>
          </label>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleConfirm}>
            Remove
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
