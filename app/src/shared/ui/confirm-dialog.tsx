import * as Dialog from '@radix-ui/react-dialog'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  title?: string
  description?: string
  confirmText?: string
  cancelText?: string
  onConfirm: () => void
}

export default function ConfirmDialog({ open, onOpenChange, title, description, confirmText = 'Confirm', cancelText = 'Cancel', onConfirm }: Props) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content
          className={cn(
            'text-foreground sm:max-w-sm w-[92vw] p-0 overflow-hidden fixed z-50 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2',
            overlayPanelClass,
          )}
        >
          <div className="px-4 pt-4 pb-2 border-b">
            <Dialog.Title className="text-base font-semibold">{title || 'Confirm'}</Dialog.Title>
            {description && <Dialog.Description className="text-xs text-muted-foreground">{description}</Dialog.Description>}
          </div>
          <div className="px-4 py-3">
            <div className="flex justify-end gap-2">
              <button className="px-3 py-1.5 rounded border" onClick={() => onOpenChange(false)}>{cancelText}</button>
              <button className="px-3 py-1.5 rounded bg-red-600 text-white" onClick={() => { onConfirm(); onOpenChange(false) }}>{confirmText}</button>
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
