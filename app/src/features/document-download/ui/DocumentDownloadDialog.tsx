import { Archive, ChevronLeft, ChevronRight, FileDigit, FileText, FileType, Globe, Loader2 } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'


import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { ScrollArea } from '@/shared/ui/scroll-area'

import type { ExportFormat } from '@/features/export'

import type { DownloadOption, DownloadOptionGroup } from '../model/options'

// Icons for supported client-side export formats
const formatIcons: Partial<Record<ExportFormat, React.ComponentType<{ className?: string }>>> = {
  archive: Archive,
  markdown: FileText,
  html: Globe,
  pdf: FileDigit,
  docx: FileType,
}

type DocumentDownloadDialogProps = {
  open: boolean
  onOpenChange: (value: boolean) => void
  primaryOptions: DownloadOption[]
  otherGroups: DownloadOptionGroup[]
  onSelect: (format: ExportFormat) => void | Promise<void>
  isPending: boolean
}

export function DocumentDownloadDialog({
  open,
  onOpenChange,
  primaryOptions,
  otherGroups,
  onSelect,
  isPending,
}: DocumentDownloadDialogProps) {
  const [showOther, setShowOther] = useState(false)

  useEffect(() => {
    if (!open) {
      setShowOther(false)
    }
  }, [open])

  const renderOption = useCallback(
    (option: DownloadOption) => {
      const Icon = formatIcons[option.format] ?? FileType
      return (
        <button
          type="button"
          key={option.format}
          onClick={() => onSelect(option.format)}
          disabled={isPending}
          className={cn(
            'group flex w-full items-center gap-4 rounded-xl border border-border/60 bg-background/70 px-4 py-4 text-left transition',
            'hover:border-primary/60 hover:shadow-sm focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2',
            'disabled:cursor-not-allowed disabled:opacity-60',
          )}
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-muted-foreground group-hover:text-primary">
            <Icon className="h-5 w-5" />
          </div>
          <div className="flex flex-col items-start text-left">
            <span className="text-sm font-medium">{option.label}</span>
            <span className="text-xs text-muted-foreground">{option.description}</span>
          </div>
          <ChevronRight className="ml-auto h-4 w-4 text-muted-foreground group-hover:text-primary" />
        </button>
      )
    },
    [isPending, onSelect],
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('sm:max-w-lg p-0', overlayPanelClass)}>
        <DialogHeader className="border-b px-6 py-4">
          <DialogTitle>Download document</DialogTitle>
          <DialogDescription>
            {showOther ? 'Select from additional Pandoc-supported formats.' : 'Select an export format for the current document.'}
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4 px-6 py-4">
          {showOther ? (
            <>
              <div className="flex items-center justify-between">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowOther(false)}
                  disabled={isPending}
                  className="-ml-2"
                >
                  <ChevronLeft className="mr-2 h-4 w-4" />
                  Back
                </Button>
              </div>
              <ScrollArea className="max-h-72 pr-2">
                <div className="flex flex-col gap-4">
                  {otherGroups.map((group) => (
                    <div key={group.title} className="space-y-2">
                      <div className="flex flex-col gap-1">
                        <span className="text-sm font-semibold">{group.title}</span>
                        {group.description ? (
                          <span className="text-xs text-muted-foreground">{group.description}</span>
                        ) : null}
                      </div>
                      <div className="flex flex-col gap-2">
                        {group.items.map((option) => renderOption(option))}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </>
          ) : (
            <>
              <div className="flex flex-col gap-3">
                {primaryOptions.map((option) => renderOption(option))}
              </div>
              <button
                type="button"
                onClick={() => setShowOther(true)}
                disabled={isPending || otherGroups.length === 0}
                className={cn(
                  'group flex w-full items-center gap-4 rounded-xl border border-dashed border-border/60 bg-background/50 px-4 py-4 text-left transition',
                  'hover:border-primary/60 hover:shadow-sm focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2',
                  'disabled:cursor-not-allowed disabled:opacity-60',
                )}
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-muted-foreground group-hover:text-primary">
                  <MoreFormatsSpinner isPending={isPending} />
                </div>
                <div className="flex flex-col items-start text-left">
                  <span className="text-sm font-medium">More formats</span>
                  <span className="text-xs text-muted-foreground">Explore all available Pandoc writers.</span>
                </div>
                <ChevronRight className="ml-auto h-4 w-4 text-muted-foreground group-hover:text-primary" />
              </button>
            </>
          )}
        </div>
        <DialogFooter className="flex items-center gap-3 border-t px-6 py-4">
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={isPending}>
            Cancel
          </Button>
          <Button onClick={() => setShowOther(true)} disabled={isPending || otherGroups.length === 0}>
            Browse all formats
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MoreFormatsSpinner({ isPending }: { isPending: boolean }) {
  if (isPending) {
    return <Loader2 className="h-4 w-4 animate-spin" />
  }
  return <ChevronRight className="h-4 w-4" />
}
