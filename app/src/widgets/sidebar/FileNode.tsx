"use client"

import { useQueries } from '@tanstack/react-query'
import {
  FileText,
  Edit,
  Trash2,
  MoreHorizontal,
  Share2,
  Globe,
  Link as LinkIcon,
  Ban,
  MessageSquare,
  Blocks,
  StickyNote,
  Bot,
  Database,
  Code,
  Image as ImageIcon,
  FileSpreadsheet,
} from 'lucide-react'
import * as LucideIcons from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import React, { useState, useCallback, memo, useEffect, useRef } from 'react'
import { toast } from 'sonner'

import useInView from '@/shared/hooks/use-in-view'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator } from '@/shared/ui/dropdown-menu'
import { Input } from '@/shared/ui/input'
import { SidebarMenuItem, SidebarMenuButton } from '@/shared/ui/sidebar'

import { GitService } from '@/entities/git'
import { getPluginKv } from '@/entities/plugin'

import { useFileTree, type DocumentNode } from '@/features/file-tree'
import { useSecondaryViewer } from '@/features/secondary-viewer'



type FileTreeRule = { pluginId: string; icon: string; identify?: { type: 'kvFlag'; key: string; path?: string; equals?: any } }

type FileNodeProps = {
  node: DocumentNode
  parentId?: string
  isSelected: boolean
  isDragging: boolean
  isDropTarget: boolean
  onSelect: (id: string, type: 'file' | 'folder') => void
  onRename: (id: string, newTitle: string) => void
  onDelete: (id: string) => void
  onDragStart: (e: React.DragEvent, id: string) => void
  onDragEnd: (e: React.DragEvent) => void
  onDragEnter: (e: React.DragEvent, id: string, type: 'file' | 'folder') => void
  onDragLeave: (e: React.DragEvent) => void
  onDrop: (e: React.DragEvent, id: string, type: 'file' | 'folder', parentId?: string) => void
  onDragOver: (e: React.DragEvent, nodeId?: string, nodeType?: 'file' | 'folder') => void
  pluginRules?: FileTreeRule[]
}

export const FileNode = memo(function FileNode({
  node,
  parentId,
  isSelected,
  isDragging,
  isDropTarget,
  onSelect,
  onRename,
  onDelete,
  onDragStart,
  onDragEnd,
  onDragEnter,
  onDragLeave,
  onDrop,
  onDragOver,
  pluginRules,
}: FileNodeProps) {
  const { sharedDocIds, publicDocIds, underSharedFolderDocIds, renameTarget, clearRenameTarget } = useFileTree()
  const { openSecondaryViewer } = useSecondaryViewer()
  const rowRef = useRef<HTMLDivElement | null>(null)
  const isRowInView = useInView(rowRef, { rootMargin: '160px' })
  const [hasBeenVisible, setHasBeenVisible] = useState(false)
  const [isEditing, setIsEditing] = useState(false)
  const [editingTitle, setEditingTitle] = useState(node.title)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
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

  useEffect(() => {
    if (isRowInView) setHasBeenVisible(true)
  }, [isRowInView])

  const guardMenuAction = useCallback((event: Event | React.SyntheticEvent, action: () => void | Promise<void>) => {
    if (menuGuardRef.current.block) {
      event.preventDefault?.()
      return
    }
    void action()
  }, [])

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
  const handleSelect = useCallback(() => { onSelect(node.id, node.type) }, [node.id, node.type, onSelect])

  useEffect(() => {
    if (renameTarget === node.id && !isEditing) {
      setIsEditing(true)
      setEditingTitle(node.title)
    }
  }, [renameTarget, node.id, node.title, isEditing])

  const kvRules = (pluginRules || []).filter(r => r.identify && r.identify.type === 'kvFlag' && !!r.identify.key)
  const shouldFetchPluginFlags = node.type === 'file' && kvRules.length > 0 && (isRowInView || hasBeenVisible)

  const kvResults = useQueries({
    queries: kvRules.map((rule) => ({
      queryKey: ['plugin-kv-flag', rule.pluginId, node.id, rule.identify!.key],
      enabled: shouldFetchPluginFlags,
      staleTime: 5 * 60 * 1000,
      queryFn: async () => {
        try {
          const response = await getPluginKv(rule.pluginId, node.id, rule.identify!.key)
          return (response as any)?.value ?? null
        } catch {
          return null
        }
      },
    }))
  })

  const getValueByPath = (obj: any, path?: string) => {
    if (!path) return obj
    const segments = path.split('.').filter(Boolean)
    let current = obj
    for (const segment of segments) {
      if (current == null) return undefined
      const candidates = [segment]
      const snake = segment.replace(/[A-Z]/g, (m) => `_${m.toLowerCase()}`)
      const camel = segment.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
      if (snake !== segment) candidates.push(snake)
      if (camel !== segment) candidates.push(camel)
      let next: any = undefined
      for (const candidate of candidates) {
        if (Object.prototype.hasOwnProperty.call(current, candidate)) {
          next = current[candidate]
          break
        }
      }
      if (next === undefined) return undefined
      current = next
    }
    return current
  }

  let chosenIcon: string | null = null
  for (let i = 0; i < kvRules.length; i++) {
    const rule = kvRules[i]
    let value: any = kvResults[i]?.data
    if (typeof value === 'string') {
      try { value = JSON.parse(value) } catch {}
    }
    if (value == null) continue

    const rawPath = rule.identify!.path
    const candidates: Array<string | undefined> = []
    if (!rawPath) {
      candidates.push(undefined)
    } else {
      candidates.push(rawPath)
      if (rawPath.includes('.')) {
        candidates.push(rawPath.replace(/\./g, '_'))
        const parts = rawPath.split('.').filter(Boolean)
        const last = parts[parts.length - 1]
        if (last) candidates.push(last)
      }
    }

    let matchedValue: any = undefined
    for (const candidate of candidates) {
      matchedValue = getValueByPath(value, candidate)
      if (matchedValue !== undefined) break
    }

    const isMatch = rule.identify!.equals !== undefined ? matchedValue === rule.identify!.equals : !!matchedValue
    if (isMatch) {
      chosenIcon = rule.icon
      break
    }
  }

  const resolveIcon = (name?: string | null): LucideIcon | null => {
    if (!name) return null
    const registry = LucideIcons as unknown as Record<string, LucideIcon>
    const variants = [name, `${name}Icon`]
    if (/[-_\s]/.test(name)) {
      const pascal = name
        .split(/[-_\s]+/)
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join('')
      variants.push(pascal, `${pascal}Icon`)
    }
    for (const variant of variants) {
      const IconComp = registry[variant]
      if (IconComp) return IconComp
    }
    const alias: Record<string, LucideIcon> = {
      Image: ImageIcon,
      Spreadsheet: FileSpreadsheet,
      MessageSquare,
      Blocks,
      StickyNote,
      Bot,
      Database,
      Code,
    }
    return alias[name] ?? null
  }

  const renderDocIcon = () => {
    const cls = 'h-4 w-4 text-muted-foreground'
    let iconName = chosenIcon
    if (!iconName) {
      const def = (pluginRules || []).find((rule) => !rule.identify && typeof rule.icon === 'string' && rule.icon)
      if (def) iconName = def.icon
    }
    const IconComp = resolveIcon(iconName)
    if (IconComp) return <IconComp className={cls} />
    return <FileText className={cls} />
  }

  return (
    <SidebarMenuItem
      className={cn(
        'relative rounded-2xl border border-transparent transition-colors duration-150 ease-out',
        isSelected && 'border-primary/40 shadow-sm',
        !isSelected && 'hover:border-border/30',
        isDropTarget && 'border-primary/40 bg-primary/10'
      )}
    >
      <div
        ref={rowRef}
        draggable={!isEditing}
        onDragStart={(e) => onDragStart(e, node.id)}
        onDragEnd={onDragEnd}
        onDragEnter={(e) => onDragEnter(e, node.id, node.type)}
        onDragLeave={onDragLeave}
        onDrop={(e) => {
          e.stopPropagation()
          onDrop(e, node.id, node.type, parentId)
        }}
        onDragOver={(e) => onDragOver(e, node.id, node.type)}
        className="relative w-full rounded-2xl"
      >
        {isEditing ? (
          <div className="flex w-full items-center gap-3 rounded-2xl bg-background/60 px-3 py-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary/15 text-primary">
              <FileText className="h-4 w-4" />
            </span>
            <Input
              value={editingTitle}
              onChange={(e) => setEditingTitle(e.target.value)}
              onBlur={handleSaveRename}
              onKeyDown={handleKeyDown}
              className="h-9 flex-1 rounded-xl border-border/50 bg-background/80 text-sm"
              autoFocus
              onFocus={(e) => e.currentTarget.select()}
            />
          </div>
        ) : (
          <div
            className={cn(
              'group/file flex w-full items-center rounded-2xl transition-colors',
              isSelected ? 'bg-primary/15' : 'bg-background/60 hover:bg-muted/10'
            )}
          >
            <SidebarMenuButton
              isActive={isSelected}
              className={cn(
                'flex-1 rounded-2xl px-2.5 py-2 text-sm font-medium transition-colors data-[active=true]:bg-transparent data-[active=true]:text-foreground data-[active=true]:hover:bg-transparent data-[active=true]:hover:text-foreground',
                isDragging && 'opacity-50',
                isSelected
                  ? 'bg-transparent text-foreground'
                  : 'text-muted-foreground hover:bg-muted/40 hover:text-foreground'
              )}
              onClick={handleSelect}
            >
              <span
                className={cn(
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-lg transition-colors',
                  isSelected ? 'bg-primary/25 text-foreground' : 'bg-muted/40 text-muted-foreground'
                )}
              >
                {renderDocIcon()}
              </span>
              <div className="flex min-w-0 flex-1 items-center gap-1.5">
                <span className="min-w-0 truncate" title={node.title}>{node.title}</span>
                {(publicDocIds.has(node.id) || sharedDocIds.has(node.id) || underSharedFolderDocIds.has(node.id)) && (
                  <span className="inline-flex shrink-0 items-center gap-1 text-muted-foreground">
                    {publicDocIds.has(node.id) && <Globe className="h-3 w-3" />}
                    {underSharedFolderDocIds.has(node.id) && <LinkIcon className="h-3 w-3" />}
                    {sharedDocIds.has(node.id) && <Share2 className="h-3 w-3" />}
                  </span>
                )}
              </div>
            </SidebarMenuButton>

            <DropdownMenu onOpenChange={handleMenuOpenChange}>
              <DropdownMenuTrigger asChild>
                <span className="ml-1 opacity-0 transition-opacity group-hover/file:opacity-100 data-[state=open]:opacity-100">
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      'flex h-8 w-8 items-center justify-center rounded-xl border transition-colors',
                      isSelected
                        ? 'border-transparent bg-transparent text-foreground hover:bg-primary/20'
                        : 'border-border/40 bg-background/70 text-muted-foreground hover:bg-muted/70 hover:text-foreground',
                      'data-[state=open]:text-foreground'
                    )}
                    onClick={(event) => event.stopPropagation()}
                  >
                    <MoreHorizontal className="h-3 w-3" />
                  </Button>
                </span>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                sideOffset={6}
                collisionPadding={8}
                className={overlayMenuClass}
              >
                <DropdownMenuItem
                  onSelect={(event) => guardMenuAction(event, handleStartRename)}
                >
                  <Edit className="h-4 w-4 mr-2" />Rename
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={(event) => guardMenuAction(event, () => openSecondaryViewer(node.id, 'document'))}
                >
                  <FileText className="h-4 w-4 mr-2" />Open in Secondary Viewer
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={(event) => guardMenuAction(event, async () => {
                    try {
                      const r = await GitService.ignoreDocument({ id: node.id })
                      const added = (r as any).added ?? 0
                      toast.success(`Ignored in Git (${added} pattern${added === 1 ? '' : 's'})`)
                    } catch (e: any) {
                      toast.error(`Failed to ignore: ${e?.message || e}`)
                    }
                  })}
                >
                  <Ban className="h-4 w-4 mr-2" />Ignore in Git
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onSelect={(event) => guardMenuAction(event, () => setShowDeleteDialog(true))}
                  className="text-red-600"
                >
                  <Trash2 className="h-4 w-4 mr-2" />Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        title={node.title}
        onConfirm={handleDelete}
      />
    </SidebarMenuItem>
  )
}, (prev, next) => (
  prev.node.id === next.node.id &&
  prev.node.title === next.node.title &&
  prev.isSelected === next.isSelected &&
  prev.isDragging === next.isDragging &&
  prev.isDropTarget === next.isDropTarget
))

export default FileNode
