"use client"

import { ChevronRight, ChevronDown, Folder, FolderOpen, Plus, Edit, Trash2, MoreHorizontal, Users, Share2, Link as LinkIcon, Ban, Archive, ArchiveRestore, Download } from 'lucide-react'
import React, { useState, useCallback, memo, useEffect, useRef } from 'react'
import { toast } from 'sonner'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { Input } from '@/shared/ui/input'
import { SidebarMenuItem, SidebarMenuButton, SidebarMenuSub } from '@/shared/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { downloadDocumentFile, useArchiveDocument, useUnarchiveDocument } from '@/entities/document'
import { ignoreFolder } from '@/entities/git'

import { useFileTree, type DocumentNode } from '@/features/file-tree'



type FolderNodeProps = {
  node: DocumentNode
  depth: number
  indentPx?: number
  suppressChildren?: boolean
  isExpanded: boolean
  isSelected: boolean
  isDragging: boolean
  isDropTarget: boolean
  hasChildDropTarget: boolean
  onToggle: (id: string) => void
  onRename: (id: string, newTitle: string) => void
  onDelete: (node: DocumentNode) => void
  onCreateNew: (parentId: string, isFolder: boolean) => void
  onDragStart: (e: React.DragEvent, id: string) => void
  onDragEnd: (e: React.DragEvent) => void
  onDragEnter: (e: React.DragEvent, id: string, type: 'file' | 'folder') => void
  onDragLeave: (e: React.DragEvent) => void
  onDrop: (e: React.DragEvent, id: string, type: 'file' | 'folder', parentId?: string) => void
  onDragOver: (e: React.DragEvent, nodeId?: string, nodeType?: 'file' | 'folder') => void
  renderChildren?: () => React.ReactNode
  onShareFolder?: (node: DocumentNode) => void
  gitEnabled?: boolean
}

export const FolderNode = memo(function FolderNode({
  node,
  depth,
  indentPx,
  suppressChildren = false,
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
  onShareFolder,
  gitEnabled = false,
}: FolderNodeProps) {
  const {
    sharedFolderIds,
    underSharedFolderFolderIds,
    renameTarget,
    clearRenameTarget,
    refreshDocuments,
    setArchivesExpanded,
  } = useFileTree()
  const [isEditing, setIsEditing] = useState(false)
  const [editingTitle, setEditingTitle] = useState(node.title)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const isMobile = useIsMobile()
  const menuGuardRef = useRef<{ block: boolean; timer?: number }>({ block: false })
  const isArchived = Boolean(node.archived)
  const isShareMount = Boolean(node.isShareMount)
  const archiveMutation = useArchiveDocument()
  const unarchiveMutation = useUnarchiveDocument()
  const [downloadPending, setDownloadPending] = useState(false)

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
    if (isArchived || isShareMount) return
    setIsEditing(true)
    setEditingTitle(node.title)
  }, [node.title, isArchived, isShareMount])
  const handleCancelRename = useCallback(() => {
    setIsEditing(false)
    setEditingTitle('')
    clearRenameTarget()
  }, [clearRenameTarget])
  const handleSaveRename = useCallback(() => {
    if (isArchived || isShareMount) return
    if (editingTitle.trim()) onRename(node.id, editingTitle.trim())
    setIsEditing(false)
    clearRenameTarget()
  }, [editingTitle, node.id, onRename, clearRenameTarget, isArchived, isShareMount])
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSaveRename(); else if (e.key === 'Escape') handleCancelRename() }, [handleSaveRename, handleCancelRename])
  const handleDelete = useCallback(() => {
    onDelete(node)
    setShowDeleteDialog(false)
  }, [node, onDelete])
  const handleCreateDocument = useCallback((e?: React.MouseEvent) => {
    e?.stopPropagation()
    if (isArchived || isShareMount) return
    onCreateNew(node.id, false)
  }, [node.id, onCreateNew, isArchived, isShareMount])
  const handleCreateFolder = useCallback((e?: React.MouseEvent) => {
    e?.stopPropagation()
    if (isArchived || isShareMount) return
    onCreateNew(node.id, true)
  }, [node.id, onCreateNew, isArchived, isShareMount])
  const handleDownloadFolder = useCallback(async () => {
    if (downloadPending) return
    if (isShareMount) return
    setDownloadPending(true)
    try {
      const filename = await downloadDocumentFile(node.id, { title: node.title, format: 'archive' })
      toast.success(`Download ready: ${filename}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to download folder'
      toast.error(message)
    } finally {
      setDownloadPending(false)
    }
  }, [downloadPending, node.id, node.title])
  const handleArchive = useCallback(async () => {
    if (isShareMount) return
    try {
      await archiveMutation.mutateAsync(node.id)
      refreshDocuments()
      setArchivesExpanded(true)
      toast.success('Folder archived')
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('refmd:document-archive-change', { detail: { id: node.id } }))
      }
    } catch (error) {
      console.error('[file-tree] archive folder failed', error)
      toast.error('Failed to archive folder')
    }
  }, [archiveMutation, isShareMount, node.id, refreshDocuments, setArchivesExpanded])

  const handleUnarchive = useCallback(async () => {
    if (isShareMount) return
    try {
      await unarchiveMutation.mutateAsync(node.id)
      refreshDocuments()
      toast.success('Folder unarchived')
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('refmd:document-archive-change', { detail: { id: node.id } }))
      }
    } catch (error) {
      console.error('[file-tree] unarchive folder failed', error)
      toast.error('Failed to unarchive folder')
    }
  }, [node.id, refreshDocuments, unarchiveMutation])

  useEffect(() => {
    if (renameTarget === node.id && !isEditing && !isArchived && !isShareMount) {
      setIsEditing(true)
      setEditingTitle(node.title)
    }
  }, [renameTarget, node.id, node.title, isEditing, isArchived, isShareMount])

  const shouldShowDropHighlight = isDropTarget || (hasChildDropTarget && isExpanded)
  const actionButtonClass = 'h-8 w-8 rounded-xl border border-border/40 bg-background/70 text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground'
  const togglePillClass = 'mr-2 h-8 w-8 rounded-xl border border-border/40 bg-background/70 text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground'

  return (
    <SidebarMenuItem
      id={`file-tree-item-${node.id}`}
      role="treeitem"
      aria-selected={isSelected}
      aria-expanded={isExpanded}
      aria-level={depth}
      data-document-node={node.id}
      className={cn(
        'relative rounded-2xl border border-transparent transition-colors duration-150 ease-out',
        shouldShowDropHighlight && 'border-primary/40 bg-primary/10',
        isSelected && 'border-primary/40 bg-primary/10 shadow-sm',
        isArchived && 'border-dashed border-border/40 opacity-80'
      )}
      style={indentPx ? { marginLeft: indentPx } : undefined}
    >
      <div
        draggable={!isEditing && !isArchived && !isShareMount}
        onDragStart={(e) => {
          if (isArchived || isShareMount) return
          onDragStart(e, node.id)
        }}
        onDragEnd={(e) => {
          if (isArchived || isShareMount) return
          onDragEnd(e)
        }}
        onDragOver={(e) => {
          if (isArchived || isShareMount) return
          e.preventDefault()
          e.stopPropagation()
          onDragOver(e, node.id, 'folder')
        }}
        onDragEnter={(e) => {
          if (isArchived || isShareMount) return
          e.preventDefault()
          e.stopPropagation()
          onDragEnter(e, node.id, 'folder')
        }}
        onDragLeave={(e) => {
          if (isArchived || isShareMount) return
          e.preventDefault()
          e.stopPropagation()
          onDragLeave(e)
        }}
        onDrop={(e) => {
          if (isArchived || isShareMount) return
          e.preventDefault()
          e.stopPropagation()
          onDrop(e, node.id, 'folder')
        }}
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
                isArchived && 'text-muted-foreground/80'
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
                {(isArchived || isShareMount || sharedFolderIds.has(node.id) || underSharedFolderFolderIds.has(node.id)) && (
                  <span className="inline-flex shrink-0 items-center gap-1 text-muted-foreground">
                    {isShareMount && <LinkIcon className="h-3 w-3" />}
                    {isArchived && <Archive className="h-3 w-3" />}
                    {sharedFolderIds.has(node.id) && <Share2 className="h-3 w-3" />}
                    {underSharedFolderFolderIds.has(node.id) && <LinkIcon className="h-3 w-3" />}
                  </span>
                )}
              </div>
            </SidebarMenuButton>
            <div className={cn('flex items-center gap-2 pl-2 transition-opacity', isMobile ? 'opacity-100' : 'opacity-0 group-hover/folder:opacity-100')}>
              {!isArchived && !isShareMount && (
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
              )}
              <DropdownMenu onOpenChange={handleMenuOpenChange}>
                <DropdownMenuTrigger asChild>
                  <span>
                    <Button variant="ghost" size="icon" className={actionButtonClass} onClick={(e) => e.stopPropagation()}>
                      <MoreHorizontal className="h-3 w-3" />
                    </Button>
                  </span>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className={overlayMenuClass}>
                  {!isArchived && !isShareMount && (
                    <>
                      <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => handleCreateDocument())}>
                        <Plus className="h-4 w-4 mr-2" />New Document
                      </DropdownMenuItem>
                      <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => handleCreateFolder())}>
                        <Folder className="h-4 w-4 mr-2" />New Folder
                      </DropdownMenuItem>
                      <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => onShareFolder?.(node))}>
                        <Users className="h-4 w-4 mr-2" />Share Folder
                      </DropdownMenuItem>
                      <DropdownMenuItem onSelect={(event) => guardMenuAction(event, handleStartRename)}>
                        <Edit className="h-4 w-4 mr-2" />Rename
                      </DropdownMenuItem>
                    </>
                  )}
                  <DropdownMenuItem
                    onSelect={(event) => guardMenuAction(event, handleDownloadFolder)}
                    disabled={downloadPending || isShareMount}
                  >
                    <Download className="h-4 w-4 mr-2" />Download Folder
                  </DropdownMenuItem>
                  {!isShareMount && gitEnabled && (
                    <DropdownMenuItem onSelect={(event) => guardMenuAction(event, async () => {
                      try {
                        const r = await ignoreFolder({ id: node.id })
                        const added = (r as any).added ?? 0
                        toast.success(`Folder ignored in Git (${added} pattern${added === 1 ? '' : 's'})`)
                      } catch (e: any) {
                        toast.error(`Failed to ignore: ${e?.message || e}`)
                      }
                    })}>
                      <Ban className="h-4 w-4 mr-2" />Ignore Folder in Git
                    </DropdownMenuItem>
                  )}
                  {!isArchived && !isShareMount && (
                    <DropdownMenuItem
                      onSelect={(event) => guardMenuAction(event, handleArchive)}
                      disabled={archiveMutation.isPending}
                    >
                      <Archive className="h-4 w-4 mr-2" />Archive
                    </DropdownMenuItem>
                  )}
                  {isArchived && !isShareMount && (
                    <DropdownMenuItem
                      onSelect={(event) => guardMenuAction(event, handleUnarchive)}
                      disabled={unarchiveMutation.isPending}
                    >
                      <ArchiveRestore className="h-4 w-4 mr-2" />Unarchive
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={(event) => guardMenuAction(event, () => setShowDeleteDialog(true))} className="text-red-600">
                    <Trash2 className="h-4 w-4 mr-2" />{isShareMount ? 'Remove from workspace' : 'Delete'}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        )}
      </div>

      {isExpanded && !suppressChildren && (
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
        description={
          isShareMount
            ? 'This removes the shared folder from your workspace.'
            : `The "${node.title}" folder and all files inside it will be deleted. This action cannot be undone.`
        }
        confirmText={isShareMount ? 'Remove' : 'Delete'}
        onConfirm={handleDelete}
      />
    </SidebarMenuItem>
  )
})

export default FolderNode
