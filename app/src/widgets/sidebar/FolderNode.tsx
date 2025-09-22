"use client"

import { ChevronRight, ChevronDown, Folder, FolderOpen, Plus, Edit, Trash2, MoreHorizontal, Users, Share2, Link as LinkIcon, Ban } from 'lucide-react'
import React, { useState, useCallback, memo, useEffect, useRef } from 'react'
import { toast } from 'sonner'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { Input } from '@/shared/ui/input'
import { SidebarMenuItem, SidebarMenuButton, SidebarMenuSub } from '@/shared/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { GitService } from '@/entities/git'

import { useFileTree, type DocumentNode } from '@/features/file-tree'
import ShareDialog from '@/features/sharing/ShareDialog'



type FolderNodeProps = {
  node: DocumentNode
  isExpanded: boolean
  isSelected: boolean
  isDragging: boolean
  isDropTarget: boolean
  hasChildDropTarget: boolean
  onToggle: (id: string) => void
  onRename: (id: string, newTitle: string) => void
  onDelete: (id: string) => void
  onCreateNew: (parentId: string, isFolder: boolean) => void
  onDragStart: (e: React.DragEvent, id: string) => void
  onDragEnd: (e: React.DragEvent) => void
  onDragEnter: (e: React.DragEvent, id: string, type: 'file' | 'folder') => void
  onDragLeave: (e: React.DragEvent) => void
  onDrop: (e: React.DragEvent, id: string, type: 'file' | 'folder', parentId?: string) => void
  onDragOver: (e: React.DragEvent, nodeId?: string, nodeType?: 'file' | 'folder') => void
  renderChildren?: () => React.ReactNode
}

export const FolderNode = memo(function FolderNode({
  node,
  isExpanded,
  isSelected,
  isDragging,
  isDropTarget,
  hasChildDropTarget,
  onToggle,
  onRename,
  onDelete,
  onCreateNew,
  onDragStart,
  onDragEnd,
  onDragEnter,
  onDragLeave,
  onDrop,
  onDragOver,
  renderChildren,
}: FolderNodeProps) {
  const { sharedFolderIds, underSharedFolderFolderIds, renameTarget, clearRenameTarget } = useFileTree()
  const [isEditing, setIsEditing] = useState(false)
  const [editingTitle, setEditingTitle] = useState(node.title)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const isMobile = useIsMobile()
  const [shareOpen, setShareOpen] = useState(false)
  const menuGuardRef = useRef<{ block: boolean; timer?: number }>({ block: false })

  const handleMenuOpenChange = useCallback((open: boolean) => {
    if (open) {
      menuGuardRef.current.block = true
      if (menuGuardRef.current.timer) window.clearTimeout(menuGuardRef.current.timer)
      menuGuardRef.current.timer = window.setTimeout(() => {
        menuGuardRef.current.block = false
        menuGuardRef.current.timer = undefined
      }, 150)
    } else {
      if (menuGuardRef.current.timer) window.clearTimeout(menuGuardRef.current.timer)
      menuGuardRef.current.block = false
      menuGuardRef.current.timer = undefined
    }
  }, [])

  useEffect(() => () => {
    if (menuGuardRef.current.timer) window.clearTimeout(menuGuardRef.current.timer)
  }, [])

  const guardMenuAction = useCallback((event: Event | React.SyntheticEvent, action: () => void | Promise<void>) => {
    if (menuGuardRef.current.block) {
      event.preventDefault?.()
      return
    }
    void action()
  }, [])

  const handleToggle = useCallback((e: React.MouseEvent) => { e.stopPropagation(); onToggle(node.id) }, [node.id, onToggle])
  const handleStartRename = useCallback(() => {
    setIsEditing(true)
    setEditingTitle(node.title)
  }, [node.title])
  const handleCancelRename = useCallback(() => {
    setIsEditing(false)
    setEditingTitle('')
    clearRenameTarget()
  }, [clearRenameTarget])
  const handleSaveRename = useCallback(() => {
    if (editingTitle.trim()) onRename(node.id, editingTitle.trim())
    setIsEditing(false)
    clearRenameTarget()
  }, [editingTitle, node.id, onRename, clearRenameTarget])
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSaveRename(); else if (e.key === 'Escape') handleCancelRename() }, [handleSaveRename, handleCancelRename])
  const handleDelete = useCallback(() => { onDelete(node.id); setShowDeleteDialog(false) }, [node.id, onDelete])
  const handleCreateDocument = useCallback((e?: React.MouseEvent) => { e?.stopPropagation(); onCreateNew(node.id, false) }, [node.id, onCreateNew])
  const handleCreateFolder = useCallback((e?: React.MouseEvent) => { e?.stopPropagation(); onCreateNew(node.id, true) }, [node.id, onCreateNew])

  useEffect(() => {
    if (renameTarget === node.id && !isEditing) {
      setIsEditing(true)
      setEditingTitle(node.title)
    }
  }, [renameTarget, node.id, node.title, isEditing])

  const shouldShowDropHighlight = isDropTarget || (hasChildDropTarget && isExpanded)
  const actionButtonClass = 'h-8 w-8 rounded-xl border border-border/40 bg-background/70 text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground'
  const togglePillClass = 'mr-2 h-8 w-8 rounded-xl border border-border/40 bg-background/70 text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground'

  return (
    <SidebarMenuItem
      className={cn(
        'relative rounded-2xl border border-transparent transition-colors duration-150 ease-out',
        shouldShowDropHighlight && 'border-primary/40 bg-primary/10',
        isSelected && 'border-primary/40 bg-primary/10 shadow-sm',
      )}
    >
      <div
        draggable={!isEditing}
        onDragStart={(e) => onDragStart(e, node.id)}
        onDragEnd={onDragEnd}
        onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); onDragOver(e, node.id, 'folder') }}
        onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); onDragEnter(e, node.id, 'folder') }}
        onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); onDragLeave(e) }}
        onDrop={(e) => { e.preventDefault(); e.stopPropagation(); onDrop(e, node.id, 'folder') }}
        className={cn('relative w-full group/folder rounded-2xl', isDropTarget && !isExpanded && 'border border-primary/40 bg-primary/10')}
      >
        {isEditing ? (
          <div className="flex flex-1 items-center gap-2 rounded-2xl bg-background/60 px-2 py-2">
            <Button variant="ghost" size="icon" className={togglePillClass} onClick={handleToggle}>
              {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            </Button>
            {isExpanded ? <FolderOpen className="mr-2 h-4 w-4 text-primary" /> : <Folder className="mr-2 h-4 w-4 text-primary" />}
            <Input
              value={editingTitle}
              onChange={(e) => setEditingTitle(e.target.value)}
              onBlur={handleSaveRename}
              onKeyDown={handleKeyDown}
              className="h-9 flex-1 rounded-xl border-border/50 bg-background/80 text-sm"
              autoFocus
              onFocus={(e) => (e.currentTarget as HTMLInputElement).select()}
            />
          </div>
        ) : (
          <div className="flex w-full items-center">
            <SidebarMenuButton
              isActive={isSelected}
              className={cn(
                'flex-1 h-11 rounded-2xl border border-transparent bg-background/60 px-2.5 text-sm font-medium text-muted-foreground backdrop-blur-sm transition-colors',
                isDragging && 'opacity-50',
                isSelected ? 'border-primary/40 bg-primary/15 text-foreground shadow-sm' : 'hover:bg-background/75 hover:text-foreground',
              )}
              onClick={handleToggle}
            >
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-muted/40">
                {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              </span>
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary">
                {isExpanded ? <FolderOpen className="h-4 w-4" /> : <Folder className="h-4 w-4" />}
              </span>
              <div className="flex min-w-0 flex-1 items-center gap-1.5">
                <span className="min-w-0 truncate" title={node.title}>{node.title}</span>
                {sharedFolderIds.has(node.id) && (
                  <span className="inline-flex shrink-0 items-center gap-1 text-muted-foreground">
                    <Share2 className="h-3 w-3" />
                  </span>
                )}
                {underSharedFolderFolderIds.has(node.id) && (
                  <span className="inline-flex shrink-0 items-center gap-1 text-muted-foreground">
                    <LinkIcon className="h-3 w-3" />
                  </span>
                )}
              </div>
            </SidebarMenuButton>
            <div className={cn('flex items-center gap-2 pl-2 transition-opacity', isMobile ? 'opacity-100' : 'opacity-0 group-hover/folder:opacity-100')}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button variant="ghost" size="icon" className={actionButtonClass} onClick={handleCreateDocument}>
                      <Plus className="h-3 w-3" />
                    </Button>
                  </span>
                </TooltipTrigger>
                <TooltipContent>
                  <p>Add document</p>
                </TooltipContent>
              </Tooltip>
              <DropdownMenu onOpenChange={handleMenuOpenChange}>
                <DropdownMenuTrigger asChild>
                  <span>
                    <Button variant="ghost" size="icon" className={actionButtonClass} onClick={(e) => e.stopPropagation()}>
                      <MoreHorizontal className="h-3 w-3" />
                    </Button>
                  </span>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className={overlayMenuClass}>
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => handleCreateDocument())}><Plus className="h-4 w-4 mr-2" />New Document</DropdownMenuItem>
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => handleCreateFolder())}><Folder className="h-4 w-4 mr-2" />New Folder</DropdownMenuItem>
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => setShareOpen(true))}><Users className="h-4 w-4 mr-2" />Share Folder</DropdownMenuItem>
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, handleStartRename)}><Edit className="h-4 w-4 mr-2" />Rename</DropdownMenuItem>
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, async () => {
                    try {
                      const r = await GitService.ignoreFolder({ id: node.id })
                      const added = (r as any).added ?? 0
                      toast.success(`Folder ignored in Git (${added} pattern${added === 1 ? '' : 's'})`)
                    } catch (e: any) {
                      toast.error(`Failed to ignore: ${e?.message || e}`)
                    }
                  })}>
                    <Ban className="h-4 w-4 mr-2" />Ignore Folder in Git
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => setShowDeleteDialog(true))} className="text-red-600"><Trash2 className="h-4 w-4 mr-2" />Delete</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        )}
      </div>

      {isExpanded && (
        <SidebarMenuSub
          className={cn('gap-0.5 relative min-h-[40px]')}
          onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); onDragOver(e, node.id, 'folder') }}
          onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); onDragEnter(e, node.id, 'folder') }}
          onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); onDragLeave(e) }}
          onDrop={(e) => { e.preventDefault(); e.stopPropagation(); onDrop(e, node.id, 'folder') }}
        >
          {node.children && node.children.length > 0 ? (
            renderChildren?.()
          ) : (
            <div className={cn('text-xs text-muted-foreground py-2 px-4', shouldShowDropHighlight && 'text-primary')}>
              {shouldShowDropHighlight ? 'Drop here' : 'Empty folder'}
            </div>
          )}
        </SidebarMenuSub>
      )}

      <ConfirmDialog
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        title={node.title}
        description={`The "${node.title}" folder and all files inside it will be deleted. This action cannot be undone.`}
        confirmText="Delete"
        onConfirm={handleDelete}
      />
      <ShareDialog open={shareOpen} onOpenChange={setShareOpen} targetId={node.id} targetType="folder" />
    </SidebarMenuItem>
  )
})

export default FolderNode
