import { Button } from '@/shared/ui/button'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/shared/ui/dialog'

interface RevokeDeviceDialogProps {
  deviceName: string | null
  open: boolean
  onClose: () => void
  onConfirm: () => void
}

export function RevokeDeviceDialog({ deviceName, open, onClose, onConfirm }: RevokeDeviceDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Revoke Device</DialogTitle>
          <DialogDescription>
            Are you sure you want to revoke{' '}
            <span className="font-medium text-foreground">{deviceName ?? 'this device'}</span>?
            It will need to be re-approved to access your account.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={onConfirm}>
            Revoke
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
