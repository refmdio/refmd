import { Link, useRouter, useRouterState } from '@tanstack/react-router'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Archive, Building2, Check, ChevronDown, ChevronRight, FileText, Github, Loader2, LogOut, Settings, Users } from 'lucide-react'
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'

import type { GitPullConflictItem, WorkspaceMembershipResponse } from '@/shared/api'
import { useShortcut } from '@/shared/hooks/use-shortcut'
import { overlayMenuClass, overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'
import FileTreeActions from '@/shared/ui/file-tree/FileTreeActions'
import { ScrollArea } from '@/shared/ui/scroll-area'
import { SidebarHeader, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuItem, SidebarMenuSkeleton } from '@/shared/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/shared/ui/tooltip'

import { downloadWorkspaceArchive } from '@/entities/document'

import { useAuthContext } from '@/features/auth'
import { useEditorContext } from '@/features/edit-document'
import {
  FileTreeProvider,
  useFileTree,
  useFileTreeInteractions,
  type DocumentNode,
} from '@/features/file-tree'
import { useFileTreeDrag } from '@/features/file-tree/lib/useFileTreeDrag'
import FileNode from '@/features/file-tree/ui/FileNode'
import FolderNode from '@/features/file-tree/ui/FolderNode'
import { GitSyncButton } from '@/features/git-sync'
import { GIT_CONFLICT_EVENT, readConflicts } from '@/features/git-sync/lib/git-conflict-store'
import { useSecondaryViewer } from '@/features/secondary-viewer'
import { ShareDialog } from '@/features/sharing'
import {
  TEMPORARY_DOCUMENT_TTL_MS,
  createTemporaryDocumentEntry,
  deleteTemporaryDocumentEntry,
  listTemporaryDocuments,
  type TemporaryDocumentMeta,
} from '@/features/temporary-document'

const userMenuIconClass = 'h-4 w-4'
const TREE_NAV_KEYS = new Set(['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Enter', ' ', 'Home', 'End'])

type VisibleTreeNode = {
  node: DocumentNode
  parentId: string | null
  depth: number
}

function SidebarUserMenu() {
  const { user, signOut, activeWorkspace } = useAuthContext()
  const [open, setOpen] = useState(false)
  const publicLink = activeWorkspace?.slug
    ? `/w/${encodeURIComponent(activeWorkspace.slug)}`
    : `/u/${encodeURIComponent(user?.name || '')}/`

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
          <Link to="/workspaces">
            <Building2 className={cn('mr-2', userMenuIconClass)} />
            <span>Workspace</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link to="/settings">
            <Settings className={cn('mr-2', userMenuIconClass)} />
            <span>Settings</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a href={publicLink} target="_blank" rel="noopener noreferrer">
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

function formatWorkspaceSecondaryText(workspace: WorkspaceMembershipResponse) {
  if (workspace.is_personal) {
    return 'Personal workspace'
  }
  const role =
    workspace.role_kind === 'system'
      ? `${(workspace.system_role || 'member').replace(/^\w/, (ltr) => ltr.toUpperCase())} role`
      : 'Custom role'
  return role
}

function WorkspaceSwitcher() {
  const { workspaces, activeWorkspaceId, switchWorkspace } = useAuthContext()
  const [open, setOpen] = useState(false)
  const [pendingId, setPendingId] = useState<string | null>(null)

  const activeWorkspace = useMemo(() => {
    if (!workspaces.length) {
      return null
    }
    return workspaces.find((ws) => ws.id === activeWorkspaceId) ?? workspaces[0]
  }, [workspaces, activeWorkspaceId])

  const canSwitch = workspaces.length > 1

  const handleSelect = useCallback(
    async (workspaceId: string) => {
      if (workspaceId === activeWorkspace?.id || pendingId) {
        return
      }
      setPendingId(workspaceId)
      try {
        await switchWorkspace(workspaceId)
        const selected = workspaces.find((ws) => ws.id === workspaceId)
        toast.success(`Switched to ${selected?.name ?? 'workspace'}`)
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'Failed to switch workspace. Please try again.'
        toast.error(message)
      } finally {
        setPendingId(null)
        setOpen(false)
      }
    },
    [activeWorkspace?.id, pendingId, switchWorkspace, workspaces],
  )

  if (!activeWorkspace) {
    return null
  }

  const triggerInner = (
    <div className="flex w-full items-center justify-between gap-3 text-left">
      <div className="min-w-0">
        <p className="truncate text-sm font-semibold text-foreground">{activeWorkspace.name}</p>
        <p className="truncate text-[11px] uppercase tracking-[0.18em] text-muted-foreground/80">
          {formatWorkspaceSecondaryText(activeWorkspace)}
        </p>
      </div>
      {pendingId ? (
        <Loader2 className="h-4 w-4 shrink-0 animate-spin text-muted-foreground" />
      ) : (
        canSwitch && <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
      )}
    </div>
  )

  if (!canSwitch) {
    return (
      <div className="rounded-2xl bg-muted/20 px-3 py-2 shadow-inner">
        {triggerInner}
      </div>
    )
  }

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          className="w-full min-w-[0] rounded-2xl bg-muted/20 px-3 py-2 text-left shadow-inner hover:bg-muted/40"
          disabled={Boolean(pendingId)}
        >
          <div className="flex w-full items-center gap-3 overflow-hidden">{triggerInner}</div>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className={cn('w-64', overlayMenuClass)} align="start">
        <DropdownMenuLabel>Switch workspace</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {workspaces.map((workspace) => (
          <DropdownMenuItem
            key={workspace.id}
            className="flex items-center gap-3 py-2"
            onClick={() => handleSelect(workspace.id)}
            disabled={Boolean(pendingId) || workspace.id === activeWorkspace.id}
          >
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{workspace.name}</p>
              <p className="truncate text-xs text-muted-foreground">
                {formatWorkspaceSecondaryText(workspace)}
              </p>
            </div>
            {workspace.id === activeWorkspace.id && (
              <Check className="ml-auto h-4 w-4 text-primary" />
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function FileTreeInner() {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const router = useRouter()
  const { openSecondaryViewer } = useSecondaryViewer()
  const {
    documents,
    archivedDocuments,
    archivesExpanded,
    setArchivesExpanded,
    expandedFolders,
    loading,
    isShare,
    shareToken,
    toggleFolder,
    expandFolder,
    expandParentFolders,
    refreshDocuments,
    updateDocuments,
    requestRename,
  } = useFileTree()
  const { activeWorkspace } = useAuthContext()
  const [selectedDocId, setSelectedDocId] = useState<string | null>(null)
  const [docPickerOpen, setDocPickerOpen] = useState(false)
  const [tempDialogOpen, setTempDialogOpen] = useState(false)
  const [tempClearAllDialogOpen, setTempClearAllDialogOpen] = useState(false)
  const [temporaryEntries, setTemporaryEntries] = useState<TemporaryDocumentMeta[]>([])
  const [shareFolderId, setShareFolderId] = useState<string | null>(null)
  const [workspaceDownloadPending, setWorkspaceDownloadPending] = useState(false)
  const [gitConflicts, setGitConflicts] = useState<GitPullConflictItem[]>(() => readConflicts())
  const openTemporaryDocument = useCallback(() => {
    if (typeof window === 'undefined') return
    const entry = createTemporaryDocumentEntry()
    router.navigate({ to: '/temporary/$id', params: { id: entry.id } })
  }, [router])
  const openTemporaryDocumentById = useCallback((id: string) => {
    router.navigate({ to: '/temporary/$id', params: { id } })
  }, [router])
  const refreshTempEntries = useCallback(() => {
    if (typeof window === 'undefined') return [] as TemporaryDocumentMeta[]
    return listTemporaryDocuments()
  }, [])
  const clearAllTemporaries = useCallback(() => {
    const list = refreshTempEntries()
    list.forEach((entry) => deleteTemporaryDocumentEntry(entry.id))
    setTemporaryEntries([])
    setTempClearAllDialogOpen(false)
  }, [refreshTempEntries])
  const openTempList = useCallback(() => {
    setTemporaryEntries(refreshTempEntries())
    setTempDialogOpen(true)
  }, [refreshTempEntries])
  const docPickerPromiseRef = React.useRef<((value: string | null) => void) | null>(null)
  const treeFocusRef = React.useRef<HTMLDivElement | null>(null)
  const treeScrollRef = React.useRef<HTMLDivElement | null>(null)
  const lastFocusRef = React.useRef<HTMLElement | null>(null)
  const treeFocusStateRef = React.useRef<'idle' | 'focused' | 'armed'>('idle')
  const { editor } = useEditorContext()
  const hasActiveDocuments = documents.length > 0
  const hasArchivedDocuments = archivedDocuments.length > 0
  const handleToggleArchives = useCallback(() => setArchivesExpanded((prev) => !prev), [setArchivesExpanded])
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

  useEffect(() => {
    const handler = () => setGitConflicts(readConflicts())
    window.addEventListener(GIT_CONFLICT_EVENT, handler)
    window.addEventListener('storage', handler)
    return () => {
      window.removeEventListener(GIT_CONFLICT_EVENT, handler)
      window.removeEventListener('storage', handler)
    }
  }, [])

  const {
    pluginMenu,
    pluginRules: fileTreeRules,
    selectableDocuments,
    createDocument,
    createFolder,
    renameDocument,
    duplicateDocument,
    deleteDocument,
    navigateToDocument,
    moveDocument,
  } = useFileTreeInteractions({
    shareToken,
    isShare,
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

  const handleWorkspaceDownload = useCallback(async () => {
    if (workspaceDownloadPending || !activeWorkspace) return
    setWorkspaceDownloadPending(true)
    try {
      const filename = await downloadWorkspaceArchive({
        workspaceId: activeWorkspace.id,
        workspaceName: activeWorkspace.name,
      })
      toast.success(`Download ready: ${filename}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to download workspace'
      toast.error(message)
    } finally {
      setWorkspaceDownloadPending(false)
    }
  }, [activeWorkspace, workspaceDownloadPending])

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

  const openNode = useCallback(async (node: DocumentNode) => {
    setSelectedDocId(node.id)
    const targetId = node.sourceId ?? node.id
    if (node.isShareMount && node.shareToken) {
      await router.navigate({
        to: '/document/$id',
        params: { id: targetId },
        search: (prev: Record<string, unknown>) => {
          const next = { ...prev }
          next.token = node.shareToken
          next.shareMount = '1'
          return next
        },
      })
      return
    }
    await navigateToDocument(targetId)
  }, [navigateToDocument, router])

  const onSelect = useCallback(async (node: DocumentNode) => {
    await openNode(node)
  }, [openNode])

  const normalizeConflictPath = useCallback((path?: string | null) => {
    if (!path) return ''
    return path.replace(/^[./]+/, '').trim().toLowerCase()
  }, [])

  const conflictForNode = useCallback(
    (node: DocumentNode): GitPullConflictItem | null => {
      if (node.type !== 'file') return null
      const targets = [normalizeConflictPath(node.path), normalizeConflictPath(node.desiredPath)].filter(Boolean)
      if (!targets.length) return null
      for (const conflict of gitConflicts) {
        const candidate = normalizeConflictPath(conflict.path)
        if (!candidate) continue
        if (targets.some((t) => candidate === t || candidate.endsWith(`/${t}`))) {
          return conflict
        }
      }
      return null
    },
    [gitConflicts, normalizeConflictPath],
  )

  // Sync selection from current URL (when user navigates elsewhere)
  useEffect(() => {
    const m = pathname.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)
    if (m && m[0]) setSelectedDocId(m[0])
  }, [pathname])

  const treeNavigation = useMemo(() => {
    const nodes: VisibleTreeNode[] = []
    const parentMap = new Map<string, string | null>()
    const indexMap = new Map<string, number>()
    const traverse = (list: DocumentNode[], depth: number, parentId: string | null) => {
      for (const entry of list) {
        nodes.push({ node: entry, parentId, depth })
        parentMap.set(entry.id, parentId)
        indexMap.set(entry.id, nodes.length - 1)
        if (entry.type === 'folder' && expandedFolders.has(entry.id) && entry.children?.length) {
          traverse(entry.children, depth + 1, entry.id)
        }
      }
    }
    traverse(documents, 1, null)
    return { nodes, parentMap, indexMap }
  }, [documents, expandedFolders])
  const visibleNodes = treeNavigation.nodes
  const nodeParentMap = treeNavigation.parentMap
  const nodeIndexMap = treeNavigation.indexMap

  const estimateRowHeight = useCallback(() => 48, [])
  const rowVirtualizer = useVirtualizer({
    count: visibleNodes.length,
    getScrollElement: () => treeScrollRef.current,
    estimateSize: estimateRowHeight,
    overscan: 12,
  })

  const scrollNodeIntoView = useCallback((nodeId: string | null) => {
    if (!nodeId) return
    const idx = nodeIndexMap.get(nodeId)
    if (typeof idx === 'number') {
      rowVirtualizer.scrollToIndex(idx, { align: 'center' })
    }
  }, [nodeIndexMap, rowVirtualizer])

  useEffect(() => {
    if (typeof document === 'undefined') return
    if (!selectedDocId) return
    if (!treeFocusRef.current) return
    if (document.activeElement !== treeFocusRef.current) return
    scrollNodeIntoView(selectedDocId)
  }, [scrollNodeIntoView, selectedDocId])

  const focusTree = useCallback(() => {
    const el = treeFocusRef.current
    if (!el) return
    if (selectedDocId && !nodeIndexMap.has(selectedDocId)) {
      expandParentFolders(selectedDocId)
    }
    let targetId = selectedDocId
    if (!targetId && visibleNodes[0]) {
      targetId = visibleNodes[0].node.id
      setSelectedDocId(targetId)
    }
    requestAnimationFrame(() => {
      el.focus()
      treeFocusStateRef.current = 'focused'
      if (targetId) {
        scrollNodeIntoView(targetId)
      }
    })
  }, [expandParentFolders, nodeIndexMap, scrollNodeIntoView, selectedDocId, setSelectedDocId, visibleNodes])

  const handleTreeFocus = useCallback(() => {
    treeFocusStateRef.current = 'focused'
  }, [])

  const handleTreeBlur = useCallback(() => {
    treeFocusStateRef.current = lastFocusRef.current ? 'armed' : 'idle'
  }, [])

  const restorePreviousFocus = useCallback(() => {
    if (typeof document === 'undefined') return false
    const treeEl = treeFocusRef.current
    const previous = lastFocusRef.current
    lastFocusRef.current = null
    const tryFocus = (node: HTMLElement | null | undefined) => {
      if (!node || node === treeEl) return false
      if (!document.contains(node)) return false
      node.focus()
      treeFocusStateRef.current = 'idle'
      return true
    }
    if (previous && tryFocus(previous)) {
      return true
    }
    if (editor) {
      try {
        editor.focus()
        treeFocusStateRef.current = 'idle'
        return true
      } catch {
        /* noop */
      }
    }
    treeFocusStateRef.current = 'idle'
    return false
  }, [editor])

  const toggleTreeFocus = useCallback(() => {
    if (typeof document === 'undefined') return
    const treeEl = treeFocusRef.current
    if (!treeEl) return
    const active = document.activeElement as HTMLElement | null

    if (active === treeEl) {
      if (!restorePreviousFocus()) {
        treeEl.blur()
      }
      return
    }

    if (treeFocusStateRef.current !== 'idle') {
      if (restorePreviousFocus()) {
        return
      }
    }

    if (active && active !== treeEl) {
      lastFocusRef.current = active
    }
    focusTree()
  }, [focusTree, restorePreviousFocus])

  useShortcut('global.file-tree.focus', () => {
    toggleTreeFocus()
  })

  const handleTreeKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.currentTarget !== event.target) return
    const normalizedKey = event.key === 'Spacebar' ? ' ' : event.key
    if (!TREE_NAV_KEYS.has(normalizedKey)) {
      return
    }
    if (!visibleNodes.length) {
      event.preventDefault()
      return
    }

    let activeId = selectedDocId
    if (activeId && !nodeIndexMap.has(activeId)) {
      expandParentFolders(activeId)
      event.preventDefault()
      return
    }
    if (!activeId) {
      activeId = visibleNodes[0]?.node.id ?? null
      if (activeId) {
        setSelectedDocId(activeId)
      }
    }

    if (!activeId) {
      event.preventDefault()
      return
    }

    const currentIndex = nodeIndexMap.get(activeId) ?? 0
    const currentEntry = visibleNodes[currentIndex]
    if (!currentEntry) {
      event.preventDefault()
      return
    }

    const moveSelection = (nextIndex: number) => {
      if (nextIndex < 0 || nextIndex >= visibleNodes.length) return
      const nextEntry = visibleNodes[nextIndex]
      if (!nextEntry) return
      if (nextEntry.node.id === selectedDocId) return
      setSelectedDocId(nextEntry.node.id)
      scrollNodeIntoView(nextEntry.node.id)
    }

    const currentNode = currentEntry.node
    switch (normalizedKey) {
      case 'ArrowDown': {
        event.preventDefault()
        if (currentIndex < visibleNodes.length - 1) {
          moveSelection(currentIndex + 1)
        }
        break
      }
      case 'ArrowUp': {
        event.preventDefault()
        if (currentIndex > 0) {
          moveSelection(currentIndex - 1)
        }
        break
      }
      case 'Home': {
        event.preventDefault()
        moveSelection(0)
        break
      }
      case 'End': {
        event.preventDefault()
        moveSelection(visibleNodes.length - 1)
        break
      }
      case 'ArrowRight': {
        event.preventDefault()
        if (currentNode.type === 'folder') {
          if (!expandedFolders.has(currentNode.id) && currentNode.children?.length) {
            expandFolder(currentNode.id)
          } else if (currentNode.children?.length) {
            moveSelection(currentIndex + 1)
          }
        } else {
          void navigateToDocument(currentNode.id)
        }
        break
      }
      case 'ArrowLeft': {
        event.preventDefault()
        if (currentNode.type === 'folder' && expandedFolders.has(currentNode.id)) {
          toggleFolder(currentNode.id)
        } else {
          const parentId = nodeParentMap.get(currentNode.id)
          if (parentId) {
            setSelectedDocId(parentId)
            scrollNodeIntoView(parentId)
          }
        }
        break
      }
      case 'Enter':
      case ' ': {
        event.preventDefault()
        if (currentNode.type === 'folder') {
          toggleFolder(currentNode.id)
        } else {
          void openNode(currentNode)
        }
        break
      }
      default:
        break
    }
  }, [expandFolder, expandParentFolders, expandedFolders, nodeIndexMap, nodeParentMap, openNode, scrollNodeIntoView, selectedDocId, setSelectedDocId, toggleFolder, visibleNodes])

  const renderVirtualRow = useCallback((entry: VisibleTreeNode) => {
    const { node, parentId, depth } = entry
    const parent = parentId ?? undefined
    const isExpanded = expandedFolders.has(node.id)
    const isSelected = selectedDocId === node.id
    const isDragging = drag.dragState.draggedItem === node.id
    const isDropTarget = drag.dragState.dropTarget === node.id
    const indentPx = Math.max(0, (depth - 1) * 14)

    if (node.type === 'folder') {
      return (
        <FolderNode
          key={node.id}
          node={node}
          depth={depth}
          indentPx={indentPx}
          suppressChildren
          isExpanded={isExpanded}
          isSelected={isSelected}
          isDragging={isDragging}
          isDropTarget={isDropTarget}
          hasChildDropTarget={false}
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
          renderChildren={undefined}
          onShareFolder={(folder) => setShareFolderId(folder.id)}
          gitEnabled
        />
      )
    }

    const conflict = conflictForNode(node)

    return (
      <FileNode
        key={node.id}
        node={node}
        parentId={parent}
        depth={depth}
        indentPx={indentPx}
        isSelected={isSelected}
        isDragging={isDragging}
        isDropTarget={isDropTarget}
        onSelect={onSelect}
        onRename={renameDocument}
        onDuplicate={duplicateDocument}
        onDelete={deleteDocument}
        onDragStart={drag.handleDragStart}
        onDragEnd={drag.handleDragEnd}
        onDragEnter={drag.handleDragEnter}
        onDragLeave={drag.handleDragLeave}
        onDragOver={drag.handleDragOver}
        onDrop={async (e, id, type) => { await handleDrop(e, id, type, parent) }}
        pluginRules={fileTreeRules}
        onOpenSecondaryViewer={openSecondaryViewer}
        gitEnabled
        conflict={conflict}
      />
    )
  }, [conflictForNode, createDocument, createFolder, deleteDocument, drag, duplicateDocument, expandedFolders, fileTreeRules, handleDrop, onSelect, openSecondaryViewer, renameDocument, selectedDocId, setShareFolderId, toggleFolder])

  const renderNestedNode = useCallback((node: DocumentNode, parentId?: string, depth = 1): React.ReactNode => {
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
          depth={depth}
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
          renderChildren={() => node.children?.map((c) => renderNestedNode(c, node.id, depth + 1))}
          onShareFolder={(folder) => setShareFolderId(folder.id)}
          gitEnabled
        />
      )
    }
    return (
      <FileNode
        key={node.id}
        node={node}
        parentId={parentId}
        depth={depth}
        isSelected={isSelected}
        isDragging={isDragging}
        isDropTarget={isDropTarget}
        onSelect={onSelect}
        onRename={renameDocument}
        onDuplicate={duplicateDocument}
        onDelete={deleteDocument}
        onDragStart={drag.handleDragStart}
        onDragEnd={drag.handleDragEnd}
        onDragEnter={drag.handleDragEnter}
        onDragLeave={drag.handleDragLeave}
        onDragOver={drag.handleDragOver}
        onDrop={async (e, id, type) => { await handleDrop(e, id, type, parentId) }}
        pluginRules={fileTreeRules}
        onOpenSecondaryViewer={openSecondaryViewer}
        gitEnabled
        conflict={conflictForNode(node)}
      />
    )
  }, [conflictForNode, createDocument, createFolder, deleteDocument, drag, duplicateDocument, expandedFolders, fileTreeRules, handleDrop, onSelect, openSecondaryViewer, renameDocument, selectedDocId, setShareFolderId, toggleFolder])

  return (
    <div className="flex h-full flex-1 flex-col">
      <div className="flex flex-1 flex-col overflow-hidden rounded-3xl border border-border/50 bg-background/95 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <SidebarHeader className="gap-0 border-b border-border/50 px-4 pb-3 pt-4">
          {isShare ? (
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground/80">Shared</p>
              <h2 className="text-lg font-semibold text-foreground">Shared Library</h2>
            </div>
          ) : (
            <div className="flex w-full flex-col items-center gap-3">
              <FileTreeActions
                className="flex flex-wrap items-center justify-center gap-3"
                onCreateDocument={() => createDocument(null)}
                onCreateFolder={() => createFolder(null)}
                pluginCommands={pluginMenu}
                onDownloadWorkspace={!isShare && activeWorkspace ? handleWorkspaceDownload : undefined}
                downloadWorkspacePending={workspaceDownloadPending}
                trailing={<GitSyncButton compact />}
                temporaryActions={{ onCreate: openTemporaryDocument, onShowList: openTempList }}
              />
            </div>
          )}
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
            <div
              ref={treeFocusRef}
              tabIndex={0}
              role="tree"
              aria-label={isShare ? 'Shared file tree' : 'Workspace file tree'}
              aria-activedescendant={selectedDocId ? `file-tree-item-${selectedDocId}` : undefined}
              className="flex h-full flex-col outline-none focus-visible:ring-2 focus-visible:ring-primary/40 focus-visible:ring-offset-2 focus-visible:ring-offset-transparent"
              onKeyDown={handleTreeKeyDown}
              onFocus={handleTreeFocus}
              onBlur={handleTreeBlur}
            >
              <div ref={treeScrollRef} className="h-full overflow-y-auto">
                <SidebarGroupContent className="h-full pr-0.5">
                  {loading ? (
                    <SidebarMenu className="gap-1.5">
                      {Array.from({ length: 8 }).map((_, i) => (
                        <SidebarMenuItem key={i} className="rounded-xl border border-border/40 bg-background/60 px-2">
                          <SidebarMenuSkeleton showIcon />
                        </SidebarMenuItem>
                      ))}
                    </SidebarMenu>
                  ) : !hasActiveDocuments && !hasArchivedDocuments ? (
                    <div className="flex h-full items-center justify-center rounded-2xl border border-dashed border-border/60 bg-background/40 px-4 py-12 text-center text-xs text-muted-foreground">
                      No documents yet. Start by creating a new note or folder.
                    </div>
                  ) : (
                    <SidebarMenu className="gap-1.5">
                      <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, position: 'relative' }}>
                        {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                          const entry = visibleNodes[virtualRow.index]
                          return (
                            <div
                              key={entry.node.id}
                              data-virtual-index={virtualRow.index}
                              style={{
                                position: 'absolute',
                                top: 0,
                                left: 0,
                                width: '100%',
                                transform: `translateY(${virtualRow.start}px)`,
                              }}
                            >
                              {renderVirtualRow(entry)}
                            </div>
                          )
                        })}
                      </div>
                    </SidebarMenu>
                  )}
                </SidebarGroupContent>
              </div>
            </div>
          </SidebarGroup>
        </SidebarContent>

        {!isShare && (
          <SidebarFooter className="px-4 py-3">
            <div className="flex flex-col gap-2">
              <Button
                variant="ghost"
                className={cn(
                  'flex w-full items-center justify-between rounded-xl border border-border/30 bg-background/80 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground',
                  !hasArchivedDocuments && 'opacity-60'
                )}
                onClick={handleToggleArchives}
                disabled={!hasArchivedDocuments}
              >
                <span className="flex items-center gap-2 text-left">
                  <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-muted/40 text-muted-foreground">
                    <Archive className="h-3.5 w-3.5" />
                  </span>
                  <span>Archives</span>
                </span>
                <span className="flex items-center gap-2">
                  <span className="rounded-full bg-muted/50 px-2 py-0.5 text-[10px] font-semibold tracking-[0.18em] text-muted-foreground">
                    {archivedDocuments.length}
                  </span>
                  <span className="flex h-5 w-5 items-center justify-center text-muted-foreground">
                    {archivesExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  </span>
                </span>
              </Button>
                  {archivesExpanded && hasArchivedDocuments && (
                    <div className="max-h-80 space-y-1.5 overflow-y-auto pr-1">
                      {archivedDocuments.map((n) => (
                        <div key={n.id}>{renderNestedNode(n)}</div>
                      ))}
                    </div>
                  )}
            </div>
          </SidebarFooter>
        )}
      </div>

      {!isShare && (
        <SidebarFooter className="mt-3 rounded-3xl border border-border/50 bg-background/95 px-4 py-3 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-background/80">
          <div className="flex items-center justify-between gap-3">
            <div className="flex-1">
              <WorkspaceSwitcher />
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

      <TemporaryScratchpadDialog
        open={tempDialogOpen}
        onOpenChange={setTempDialogOpen}
        entries={temporaryEntries}
        onOpenTemporary={openTemporaryDocumentById}
        onRequestClearAll={() => setTempClearAllDialogOpen(true)}
      />

      <ConfirmDialog
        open={tempClearAllDialogOpen}
        onOpenChange={setTempClearAllDialogOpen}
        title="Delete all temporary notes?"
        description="This removes every temporary document stored on this browser. This cannot be undone."
        confirmText="Delete all"
        onConfirm={clearAllTemporaries}
      />

      {shareFolderId && (
        <ShareDialog
          open={shareFolderId !== null}
          onOpenChange={(open) => {
            if (!open) setShareFolderId(null)
          }}
          targetId={shareFolderId}
          targetType="folder"
        />
      )}
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

function TemporaryScratchpadDialog({
  open,
  onOpenChange,
  entries,
  onOpenTemporary,
  onRequestClearAll,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  entries: TemporaryDocumentMeta[]
  onOpenTemporary: (id: string) => void
  onRequestClearAll: () => void
}) {
  const formattedEntries = useMemo(() => entries.slice().sort((a, b) => b.updatedAt - a.updatedAt), [entries])

  const handleOpen = useCallback((id: string) => {
    onOpenTemporary(id)
    onOpenChange(false)
  }, [onOpenChange, onOpenTemporary])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('max-w-md', overlayPanelClass)}>
        <DialogHeader>
          <DialogTitle>Temporary drafts on this device</DialogTitle>
          <DialogDescription>Each temporary note persists locally for 24 hours after its last edit.</DialogDescription>
        </DialogHeader>
        {formattedEntries.length === 0 ? (
          <p className="text-sm text-muted-foreground">No temporary drafts detected on this device.</p>
        ) : (
          <div className="max-h-80 space-y-2 overflow-y-auto pr-1">
            {formattedEntries.map((entry) => (
              <button
                type="button"
                key={entry.id}
                onClick={() => handleOpen(entry.id)}
                className="w-full rounded-2xl border border-border/60 bg-background/80 p-3 text-left transition hover:border-primary/50"
              >
                <p className="text-sm font-medium text-foreground">{entry.preview?.trim() || 'Untitled temporary note'}</p>
                <p className="text-xs text-muted-foreground">
                  Created {formatDate(entry.createdAt)} · Expires {formatExpiry(entry.updatedAt)}
                </p>
              </button>
            ))}
          </div>
        )}
        <DialogFooter>
          {formattedEntries.length > 0 && (
            <Button variant="destructive" onClick={onRequestClearAll}>Delete all</Button>
          )}
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleString()
}

function formatExpiry(updatedAt: number) {
  const expiresAt = updatedAt + TEMPORARY_DOCUMENT_TTL_MS
  const remainingMs = expiresAt - Date.now()
  if (remainingMs <= 0) return 'soon'
  const hours = Math.floor(remainingMs / (60 * 60 * 1000))
  const minutes = Math.floor((remainingMs % (60 * 60 * 1000)) / (60 * 1000))
  if (hours <= 0) return `in ${minutes} min`
  return `in ${hours}h ${minutes.toString().padStart(2, '0')}m`
}
