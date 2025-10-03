import { Link, useRouter, useRouterState } from '@tanstack/react-router'
import { Blocks, Eye, FileText, Github, LogOut, Settings, Users } from 'lucide-react'
import React, { useCallback, useEffect, useState } from 'react'

import { overlayMenuClass, overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import { ScrollArea } from '@/shared/ui/scroll-area'
import { SidebarHeader, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuItem, SidebarMenuSkeleton } from '@/shared/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { useAuthContext } from '@/features/auth'
import {
  FileTreeProvider,
  useFileTree,
  useFileTreeInteractions,
  type DocumentNode,
} from '@/features/file-tree'
import { GitSyncButton } from '@/features/git-sync'

import FileNode from '@/widgets/sidebar/FileNode'
import FileTreeActions from '@/widgets/sidebar/FileTreeActions'
import FolderNode from '@/widgets/sidebar/FolderNode'
import { useFileTreeDrag } from '@/widgets/sidebar/useFileTreeDrag'

const userMenuIconClass = 'h-4 w-4'

function SidebarUserMenu() {
  const { user, signOut } = useAuthContext()
  const [open, setOpen] = useState(false)

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="h-9 w-9 rounded-full border border-border/40 bg-background/70 text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground">
                <Settings className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
          </span>
        </TooltipTrigger>
        <TooltipContent side="bottom">Settings</TooltipContent>
      </Tooltip>
      <DropdownMenuContent className={cn('w-56', overlayMenuClass)} align="end">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col space-y-1">
            <p className="text-sm font-medium leading-none">{user?.name || 'User'}</p>
            <p className="text-xs leading-none text-muted-foreground">{user?.email || ''}</p>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to="/profile">
            <FileText className={cn('mr-2', userMenuIconClass)} />
            <span>Profile</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link to="/visibility">
            <Eye className={cn('mr-2', userMenuIconClass)} />
            <span>Visibility</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link to="/plugins">
            <Blocks className={cn('mr-2', userMenuIconClass)} />
            <span>Plugins</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a href={`/u/${encodeURIComponent(user?.name || '')}/`} target="_blank" rel="noopener noreferrer">
            <Users className={cn('mr-2', userMenuIconClass)} />
            <span>Public pages</span>
          </a>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <a href="https://github.com/refmdio/refmd" target="_blank" rel="noopener noreferrer">
            <Github className={cn('mr-2', userMenuIconClass)} />
            <span>GitHub</span>
          </a>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={async () => {
            await signOut()
            setOpen(false)
          }}
        >
          <LogOut className={cn('mr-2', userMenuIconClass)} />
          <span>Sign out</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function FileTreeInner() {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const { user } = useAuthContext()
  const router = useRouter()
  const { documents, expandedFolders, loading, shareToken, toggleFolder, expandFolder, refreshDocuments, updateDocuments, requestRename } = useFileTree()
  const isShare = shareToken.length > 0
  const [selectedDocId, setSelectedDocId] = useState<string | null>(null)
  const [docPickerOpen, setDocPickerOpen] = useState(false)
  const docPickerPromiseRef = React.useRef<((value: string | null) => void) | null>(null)
  const isDescendant = useCallback((ancestorId: string, nodeId: string): boolean => {
    const stack: DocumentNode[] = []
    const pushChildren = (id: string) => {
      const rec = (nodes: DocumentNode[]) => {
        for (const n of nodes) {
          if (n.id === id) { if (n.children) stack.push(...n.children); return true }
          if (n.children && rec(n.children)) return true
        }
        return false
      }
      rec(documents)
    }
    pushChildren(ancestorId)
    while (stack.length) {
      const n = stack.pop()!
      if (n.id === nodeId) return true
      if (n.children) stack.push(...n.children)
    }
    return false
  }, [documents])

  const requestDocumentSelection = useCallback(() => {
    return new Promise<string | null>((resolve) => {
      docPickerPromiseRef.current = resolve
      setDocPickerOpen(true)
    })
  }, [])

  const closeDocumentPicker = useCallback((value: string | null) => {
    const resolver = docPickerPromiseRef.current
    docPickerPromiseRef.current = null
    if (resolver) resolver(value)
    setDocPickerOpen(false)
  }, [])

  useEffect(() => {
    return () => {
      if (docPickerPromiseRef.current) {
        docPickerPromiseRef.current(null)
        docPickerPromiseRef.current = null
      }
    }
  }, [])

  const {
    pluginMenu,
    pluginRules: fileTreeRules,
    selectableDocuments,
    createDocument,
    createFolder,
    renameDocument,
    deleteDocument,
    navigateToDocument,
    moveDocument,
  } = useFileTreeInteractions({
    shareToken,
    documents,
    getSelectedDocumentId: () => selectedDocId,
    setSelectedDocumentId: setSelectedDocId,
    refreshDocuments,
    expandFolder,
    updateDocuments,
    requestRename,
    requestDocumentId: requestDocumentSelection,
    navigate: (options) => router.navigate(options as any),
  })

  const drag = useFileTreeDrag({
    onMove: async (nodeId, targetId) => {
      if (targetId && isDescendant(nodeId, targetId)) return
      await moveDocument(nodeId, targetId)
    },
  })

  const handleDrop = useCallback(
    async (
      e: React.DragEvent,
      targetId?: string,
      targetType?: DocumentNode['type'],
      parentId?: string,
    ) => {
      if (targetType === 'file') {
        await drag.handleDrop(e, parentId, 'folder', parentId)
      } else {
        await drag.handleDrop(e, targetId, targetType, parentId)
      }
    },
    [drag],
  )
  const onSelect = useCallback(async (id: string, _type: DocumentNode['type']) => {
    await navigateToDocument(id)
  }, [navigateToDocument])

  // Sync selection from current URL (when user navigates elsewhere)
  useEffect(() => {
    const m = pathname.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)
    if (m && m[0]) setSelectedDocId(m[0])
  }, [pathname])

  const renderNode = useCallback((node: DocumentNode, parentId?: string): React.ReactNode => {
    const isExpanded = expandedFolders.has(node.id)
    const isSelected = selectedDocId === node.id
    const isDragging = drag.dragState.draggedItem === node.id
    const isDropTarget = drag.dragState.dropTarget === node.id
    const childHasDropTarget = false
    if (node.type === 'folder') {
    return (
      <FolderNode
        key={node.id}
        node={node}
          isExpanded={isExpanded}
          isSelected={isSelected}
          isDragging={isDragging}
          isDropTarget={isDropTarget}
          hasChildDropTarget={childHasDropTarget}
          onToggle={toggleFolder}
          onRename={renameDocument}
          onDelete={deleteDocument}
          onCreateNew={(pid, isFolder) => (isFolder ? createFolder(pid) : createDocument(pid))}
          onDragStart={drag.handleDragStart}
          onDragEnd={drag.handleDragEnd}
          onDragEnter={drag.handleDragEnter}
          onDragLeave={drag.handleDragLeave}
          onDragOver={drag.handleDragOver}
          onDrop={async (e, id) => { await drag.handleDrop(e, id, 'folder') }}
          renderChildren={() => node.children?.map((c) => renderNode(c, node.id))}
        />
      )
    }
    return (
      <FileNode
        key={node.id}
        node={node}
        parentId={parentId}
        isSelected={isSelected}
        isDragging={isDragging}
        isDropTarget={isDropTarget}
        onSelect={onSelect}
        onRename={renameDocument}
        onDelete={deleteDocument}
        onDragStart={drag.handleDragStart}
        onDragEnd={drag.handleDragEnd}
        onDragEnter={drag.handleDragEnter}
        onDragLeave={drag.handleDragLeave}
        onDragOver={drag.handleDragOver}
        onDrop={async (e, id, type) => { await handleDrop(e, id, type, parentId) }}
        pluginRules={fileTreeRules}
      />
    )
  }, [expandedFolders, toggleFolder, renameDocument, deleteDocument, onSelect, createDocument, drag, handleDrop, createFolder, fileTreeRules])

  return (
    <div className="flex h-full flex-1 flex-col">
      <div className="flex flex-1 flex-col overflow-hidden rounded-3xl border border-border/50 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <SidebarHeader className="gap-0 border-b border-border/50 px-4 pb-3 pt-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground/80">{isShare ? 'Shared' : 'Workspace'}</p>
              <h2 className="text-lg font-semibold text-foreground">{isShare ? 'Shared Library' : 'Files'}</h2>
            </div>
            {!isShare && (
              <div className="flex items-center gap-2">
                <FileTreeActions
                  onCreateDocument={() => createDocument(null)}
                  onCreateFolder={() => createFolder(null)}
                  pluginCommands={pluginMenu}
                  trailing={<GitSyncButton compact />}
                />
              </div>
            )}
          </div>
        </SidebarHeader>

        <SidebarContent
          className="relative flex-1 px-1.5 py-3"
          onDragEnter={(e) => { if (!isShare) drag.handleDragEnter(e as any, '', 'folder') }}
          onDragOver={(e) => { if (!isShare) { drag.handleDragOver(e as any); drag.handleDragOver(e as any, '', 'folder') } }}
          onDragLeave={(e) => { if (!isShare) drag.handleDragLeave(e as any) }}
          onDrop={async (e) => { if (!isShare) await drag.handleDrop(e as any, undefined, 'folder') }}
        >
          {((drag.dragState.draggedItem && drag.dragState.dropTarget === '') || (drag.dragState.isExternalDrag && drag.dragState.dropTarget === '')) && (
            <div className="pointer-events-none absolute inset-2 rounded-2xl border border-primary/30 bg-primary/5" />
          )}
          {!isShare && drag.dragState.isExternalDrag && !drag.dragState.dropTarget && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <p className="rounded-full border border-primary/40 bg-primary/10 px-4 py-1 text-sm font-medium text-primary">Drop files here to add to workspace</p>
            </div>
          )}

          <SidebarGroup className="h-full overflow-hidden rounded-2xl bg-muted/10 px-1.5 py-3">
            <SidebarGroupContent className="h-full overflow-y-auto pr-0.5">
              {loading ? (
                <SidebarMenu className="gap-1.5">
                  {Array.from({ length: 8 }).map((_, i) => (
                    <SidebarMenuItem key={i} className="rounded-xl border border-border/40 bg-background/60 px-2">
                      <SidebarMenuSkeleton showIcon />
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              ) : documents.length === 0 ? (
                <div className="flex h-full items-center justify-center rounded-2xl border border-dashed border-border/60 bg-background/40 px-4 py-12 text-center text-xs text-muted-foreground">
                  No documents yet. Start by creating a new note or folder.
                </div>
              ) : (
                <SidebarMenu className="gap-1.5">
                  {documents.map((n) => renderNode(n))}
                </SidebarMenu>
              )}
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </div>

      {!isShare && (
        <SidebarFooter className="mt-3 rounded-3xl border border-border/50 bg-background/95 px-4 py-3 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-foreground">{user?.name || 'Guest'}</p>
              {user?.email && <p className="truncate text-xs text-muted-foreground/70">{user.email}</p>}
            </div>
            <SidebarUserMenu />
          </div>
        </SidebarFooter>
      )}

      <DocumentPickerDialog
        open={docPickerOpen}
        documents={selectableDocuments}
        onCancel={() => closeDocumentPicker(null)}
        onSelect={(id) => closeDocumentPicker(id)}
      />
    </div>
  )
}

export default function FileTree() {
  return (
    <FileTreeProvider>
      <FileTreeInner />
    </FileTreeProvider>
  )
}

function DocumentPickerDialog({
  open,
  documents,
  onCancel,
  onSelect,
}: {
  open: boolean
  documents: Array<{ id: string; title: string; path: string }>
  onCancel: () => void
  onSelect: (id: string) => void
}) {
  return (
    <Dialog open={open} onOpenChange={(value) => { if (!value) onCancel() }}>
      <DialogContent className={cn('max-w-md', overlayPanelClass)}>
        <DialogHeader>
          <DialogTitle>Select a document</DialogTitle>
          <DialogDescription>Choose a document to run this plugin command.</DialogDescription>
        </DialogHeader>
        {documents.length === 0 ? (
          <p className="text-sm text-muted-foreground">No documents available.</p>
        ) : (
          <ScrollArea className="max-h-60 rounded border">
            <div className="p-2 flex flex-col gap-2">
              {documents.map((doc) => (
                <Button
                  key={doc.id}
                  variant="outline"
                  className="justify-start"
                  onClick={() => onSelect(doc.id)}
                >
                  <span className="truncate text-left">
                    <span className="block font-medium text-foreground">{doc.title}</span>
                    <span className="block text-xs text-muted-foreground truncate">{doc.path}</span>
                  </span>
                </Button>
              ))}
            </div>
          </ScrollArea>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
