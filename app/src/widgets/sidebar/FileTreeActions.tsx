import { Plus, Folder, Blocks, Image as ImageIcon, FileSpreadsheet } from 'lucide-react'
import * as LucideIcons from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

type PluginAction = {
  title: string
  onClick?: () => void
  icon?: string
  disabled?: boolean
}

type Props = {
  onCreateDocument: () => void
  onCreateFolder?: () => void
  pluginCommands?: PluginAction[]
  trailing?: React.ReactNode
}

// Minimal actions aligned to current API (document creation + refresh).
const iconCls = 'h-4 w-4 mr-2 text-muted-foreground'
const iconAliases: Record<string, LucideIcon> = {
  Image: ImageIcon,
  Spreadsheet: FileSpreadsheet,
  Blocks,
}

function renderPluginIcon(name?: string) {
  const registry = LucideIcons as unknown as Record<string, LucideIcon>
  if (name) {
    const variants = [name, `${name}Icon`]
    if (/[-_\s]/.test(name)) {
      const pascal = name
        .split(/[-_\s]+/)
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join('')
      variants.push(pascal, `${pascal}Icon`)
    }
    for (const candidate of variants) {
      const IconComp = registry[candidate]
      if (IconComp) return <IconComp className={iconCls} />
    }
    const Alias = iconAliases[name]
    if (Alias) return <Alias className={iconCls} />
  }
  return <Blocks className={iconCls} />
}

export default function FileTreeActions({ onCreateDocument, onCreateFolder, pluginCommands, trailing }: Props) {
  const buttonClass = cn(
    'h-9 w-9 rounded-full border border-border/40 bg-background/70 text-muted-foreground transition-colors',
    'hover:bg-muted/70 hover:text-foreground disabled:opacity-50'
  )
  const hasEnabledPluginCommand = pluginCommands?.some((cmd) => !cmd.disabled && typeof cmd.onClick === 'function') ?? false

  return (
    <div className="flex items-center gap-2 rounded-2xl border border-border/40 bg-muted/20 px-2 py-1">
      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <Button variant="ghost" size="icon" className={buttonClass} onClick={onCreateDocument}>
              <Plus className="h-4 w-4" />
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent>New document</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <Button variant="ghost" size="icon" className={buttonClass} onClick={onCreateFolder} disabled={!onCreateFolder}>
              <Folder className="h-4 w-4" />
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent>{onCreateFolder ? 'New folder' : 'New folder (coming soon)'}</TooltipContent>
      </Tooltip>

      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <span>
              <DropdownMenuTrigger asChild>
                <span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={buttonClass}
                    disabled={!pluginCommands || pluginCommands.length === 0 || !hasEnabledPluginCommand}
                  >
                    <Blocks className="h-4 w-4" />
                  </Button>
                </span>
              </DropdownMenuTrigger>
            </span>
          </TooltipTrigger>
          <TooltipContent>Plugins</TooltipContent>
        </Tooltip>
        <DropdownMenuContent align="end" className={overlayMenuClass}>
          {(pluginCommands && pluginCommands.length > 0) ? pluginCommands.map((cmd, i) => (
            <DropdownMenuItem
              key={i}
              onClick={() => { if (cmd.onClick && !cmd.disabled) { cmd.onClick() } }}
              disabled={cmd.disabled || typeof cmd.onClick !== 'function'}
            >
              {renderPluginIcon(cmd.icon)}
              {cmd.title || 'Command'}
            </DropdownMenuItem>
          )) : (
            <DropdownMenuItem disabled>No plugin commands</DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      {trailing}
    </div>
  )
}
