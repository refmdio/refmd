import {
  ArrowUpDown,
  Ban,
  Bold,
  CheckSquare,
  Code,
  Heading1,
  Italic,
  Link as LinkIcon,
  List,
  ListOrdered,
  Minus,
  Quote,
  Strikethrough,
  Table,
  Upload,
} from 'lucide-react'
import React, { memo, useCallback } from 'react'

import { cn } from '@/shared/lib/utils'
import type { ViewMode } from '@/shared/types/view-mode'
import { Button } from '@/shared/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import VimToggle from './VimToggle'

export interface EditorToolbarProps {
  onCommand: (command: string, value?: number) => void
  className?: string
  syncScroll?: boolean
  onSyncScrollToggle?: () => void
  onFileUpload?: () => void
  viewMode?: ViewMode
  isVimMode?: boolean
  onVimModeToggle?: () => void
  readOnly?: boolean
}

interface ToolbarButton {
  icon: React.ReactNode
  command: string
  title: string
  value?: number
}

function EditorToolbarComponent({
  onCommand,
  className,
  syncScroll,
  onSyncScrollToggle,
  onFileUpload,
  viewMode,
  isVimMode,
  onVimModeToggle,
  readOnly,
}: EditorToolbarProps) {
  const buttonClass = cn(
    'h-10 w-10 rounded-2xl border border-border/40 bg-muted/40 text-muted-foreground transition-colors',
    'hover:bg-muted/70 hover:text-foreground disabled:opacity-40'
  )

  const buttonGroups: Array<{ label: string; buttons: ToolbarButton[] }> = [
    {
      label: 'Text',
      buttons: [
        { icon: <Bold className="h-4 w-4" />, command: 'bold', title: 'Bold' },
        { icon: <Italic className="h-4 w-4" />, command: 'italic', title: 'Italic' },
        { icon: <Strikethrough className="h-4 w-4" />, command: 'strikethrough', title: 'Strikethrough' },
        { icon: <Heading1 className="h-4 w-4" />, command: 'heading', title: 'Heading 1', value: 1 },
        { icon: <LinkIcon className="h-4 w-4" />, command: 'link', title: 'Link' },
        { icon: <Quote className="h-4 w-4" />, command: 'quote', title: 'Quote' },
      ],
    },
    {
      label: 'Lists',
      buttons: [
        { icon: <List className="h-4 w-4" />, command: 'unordered-list', title: 'List' },
        { icon: <ListOrdered className="h-4 w-4" />, command: 'ordered-list', title: 'Numbered List' },
        { icon: <CheckSquare className="h-4 w-4" />, command: 'task-list', title: 'Task List' },
      ],
    },
    {
      label: 'Insert',
      buttons: [
        { icon: <Code className="h-4 w-4" />, command: 'code', title: 'Code' },
        { icon: <Table className="h-4 w-4" />, command: 'table', title: 'Table' },
        { icon: <Minus className="h-4 w-4" />, command: 'horizontal-rule', title: 'Horizontal Rule' },
      ],
    },
  ]

  const renderButton = useCallback((button: ToolbarButton, index: number) => {
    const disabled = Boolean(readOnly)
    return (
      <Tooltip key={`${button.command}-${index}`}>
        <TooltipTrigger asChild>
          <span>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => onCommand(button.command, button.value)}
              disabled={disabled}
              className={buttonClass}
            >
              {button.icon}
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent>{button.title}</TooltipContent>
      </Tooltip>
    )
  }, [onCommand, readOnly])

  const hasUtilityControls = Boolean(
    (onFileUpload && !readOnly) || (viewMode === 'split' && onSyncScrollToggle) || onVimModeToggle,
  )

  return (
    <div className={cn('flex flex-col gap-5', className)}>
      <div className="flex flex-col gap-4">
        {buttonGroups.map((group) => (
          <div key={group.label} className="space-y-2">
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground/70">
              {group.label}
            </p>
            <div className="grid grid-cols-3 gap-2">
              {group.buttons.map((button, index) => renderButton(button, index))}
            </div>
          </div>
        ))}
      </div>

      {hasUtilityControls && (
        <>
          <div className="h-px w-full bg-border/50" />
          <div className="space-y-2">
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground/70">
              Utilities
            </p>
            <div className="grid grid-cols-3 gap-2">
              {onFileUpload && !readOnly && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={onFileUpload}
                        className={buttonClass}
                      >
                        <Upload className="h-4 w-4" />
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>Upload file</TooltipContent>
                </Tooltip>
              )}

              {viewMode === 'split' && onSyncScrollToggle && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={onSyncScrollToggle}
                        className={cn(buttonClass, 'relative')}
                      >
                        <ArrowUpDown className="h-4 w-4" />
                        {!syncScroll && <Ban className="absolute inset-0 m-auto h-4 w-4 text-red-400" />}
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>{syncScroll ? 'Disable scroll sync' : 'Enable scroll sync'}</TooltipContent>
                </Tooltip>
              )}

              {onVimModeToggle && (
                <VimToggle
                  isVimMode={isVimMode || false}
                  onToggle={onVimModeToggle}
                  className={cn(buttonClass, 'font-semibold')}
                />
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

const EditorToolbar = memo(EditorToolbarComponent)
export default EditorToolbar
