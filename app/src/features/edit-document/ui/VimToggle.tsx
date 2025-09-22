import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

type Props = { isVimMode: boolean; onToggle: () => void; className?: string }

export default function VimToggle({ isVimMode, onToggle, className }: Props) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>
          <Button
            variant="ghost"
            size="icon"
            onClick={onToggle}
            className={cn(
              'flex h-10 w-10 flex-col items-center justify-center gap-1 rounded-2xl text-[11px] font-semibold uppercase tracking-wide transition-colors',
              'font-mono text-muted-foreground hover:bg-muted/70 hover:text-foreground',
              isVimMode ? 'bg-muted/60 text-foreground ring-2 ring-inset ring-primary/50' : 'opacity-90',
              className,
            )}
          >
            <span>Vim</span>
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{isVimMode ? 'Disable Vim mode' : 'Enable Vim mode'}</TooltipContent>
    </Tooltip>
  )
}
