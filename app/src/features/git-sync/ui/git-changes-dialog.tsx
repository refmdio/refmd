import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/shared/ui/dialog'

import { WorkingDiffPanel } from './working-diff-panel'

type Props = { open: boolean; onOpenChange: (open: boolean) => void }

export default function GitChangesDialog({ open, onOpenChange }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('sm:max-w-[70vw] max-w-[90vw] h-[80vh] p-0 flex flex-col', overlayPanelClass)}>
        <DialogHeader className="px-6 py-4 border-b flex-shrink-0">
          <DialogTitle>Git Changes</DialogTitle>
        </DialogHeader>
        <div className="flex-1 overflow-hidden">
          <WorkingDiffPanel className="h-full" />
        </div>
      </DialogContent>
    </Dialog>
  )
}
