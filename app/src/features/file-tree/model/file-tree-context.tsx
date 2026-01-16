import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRouterState } from '@tanstack/react-router'
import React, { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react'

import { useShareToken } from '@/shared/contexts/share-token-context'

import { listDocuments } from '@/entities/document'
import { listWorkspacePublicDocuments } from '@/entities/public'
import { browseShare, listActiveShares, shareKeys, shareMountsQuery, useShareMounts } from '@/entities/share'
import { meQuery } from '@/entities/user'

import { useAuthContext } from '@/features/auth'
import type { DocumentNode } from '@/features/file-tree/model/types'

type CtxType = {
  documents: DocumentNode[]
  archivedDocuments: DocumentNode[]
  expandedFolders: Set<string>
  loading: boolean
  sharedDocIds: Set<string>
  sharedFolderIds: Set<string>
  publicDocIds: Set<string>
  underSharedFolderDocIds: Set<string>
  underSharedFolderFolderIds: Set<string>
  isShare: boolean
  shareToken: string
  archivesExpanded: boolean
  setArchivesExpanded: React.Dispatch<React.SetStateAction<boolean>>
  toggleFolder: (id: string) => void
  expandFolder: (id: string) => void
  expandParentFolders: (id: string) => void
  refreshDocuments: () => void
  updateDocuments: (docs: DocumentNode[]) => void
  requestRename: (id: string) => void
  renameTarget: string | null
  clearRenameTarget: () => void
}

const FileTreeCtx = createContext<CtxType | null>(null)

type DbDoc = {
  id: string
  source_id?: string
  title: string
  parent_id?: string | null
  created_at: string
  updated_at: string
  type?: 'document' | 'folder'
  archived_at?: string | null
  archived_parent_id?: string | null
  owner_id?: string | null
  workspace_id?: string | null
  share_token?: string
  is_share_mount?: boolean
  share_mount_id?: string
  created_by_plugin?: string | null
  path?: string | null
  desired_path?: string | null
}

type BuildTreeOptions = {
  useArchivedParent?: boolean
  fallbackInfo?: Map<string, { id: string; title: string; type: DocumentNode['type']; parent_id?: string | null }>
}

function buildTree(docs: DbDoc[], options?: BuildTreeOptions): DocumentNode[] {
  const useArchivedParent = options?.useArchivedParent ?? false
  const fallbackInfo = options?.fallbackInfo
  const nodeMap = new Map<string, DocumentNode>()
  const parentRef = new Map<string, string | undefined>()

  const ensurePlaceholder = (id: string | undefined) => {
    if (!id || nodeMap.has(id)) return
    const info = fallbackInfo?.get(id)
    if (!info || info.type !== 'folder') return
    const placeholder: DocumentNode = {
      id: info.id,
      title: info.title,
      type: 'folder',
      children: [],
      archived: true,
    }
    nodeMap.set(id, placeholder)
    const parentId = (useArchivedParent ? info.parent_id ?? undefined : info.parent_id ?? undefined) || undefined
    if (parentId === id) {
      parentRef.set(id, undefined)
      return
    }
    parentRef.set(id, parentId)
    if (parentId) ensurePlaceholder(parentId)
  }

  docs.forEach((d) => {
    const type: DocumentNode['type'] = d.type === 'folder' ? 'folder' : 'file'
    nodeMap.set(d.id, {
      id: d.id,
      sourceId: d.source_id,
      title: d.title,
      type,
      path: d.path ?? null,
      desiredPath: d.desired_path ?? null,
      children: [],
      created_at: d.created_at,
      updated_at: d.updated_at,
      archived: Boolean(d.archived_at),
      shareToken: d.share_token,
      isShareMount: d.is_share_mount,
      shareMountId: d.share_mount_id,
      createdByPlugin: d.created_by_plugin ?? null,
    })
    const parentId = (useArchivedParent ? d.archived_parent_id : d.parent_id) ?? undefined
    parentRef.set(d.id, parentId ?? undefined)
    if (useArchivedParent && parentId && !nodeMap.has(parentId)) {
      ensurePlaceholder(parentId)
    }
  })

  const roots: DocumentNode[] = []
  nodeMap.forEach((node, id) => {
    node.children = node.children ?? []
    const parentId = parentRef.get(id)
    if (parentId && nodeMap.has(parentId) && parentId !== id) {
      const parent = nodeMap.get(parentId)!
      parent.children = parent.children ?? []
      if (!parent.children!.includes(node)) parent.children!.push(node)
      if (parent.type === 'file') parent.type = 'folder'
    } else {
      roots.push(node)
    }
  })

  const sortTree = (nodes: DocumentNode[]): DocumentNode[] => {
    nodes.sort((a, b) => {
      if (a.type !== b.type) {
        return a.type === 'folder' ? -1 : 1
      }
      return a.title.localeCompare(b.title)
    })
    nodes.forEach((n) => {
      if (n.children && n.children.length) sortTree(n.children)
    })
    return nodes
  }
  return sortTree(roots)
}

export function FileTreeProvider({ children }: { children: React.ReactNode }) {
  const shareToken = useShareToken() ?? ''
  const shareMountFlag = useRouterState({
    select: (state) => {
      const search = (state.location?.search ?? {}) as Record<string, unknown>
      const raw = (search as any)?.shareMount ?? (search as any)?.share_mount
      if (raw == null) return false
      if (typeof raw === 'string') {
        const normalized = raw.trim().toLowerCase()
        return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on'
      }
      if (typeof raw === 'number') return raw === 1
      return Boolean(raw)
    },
  })
  const isShare = shareToken.length > 0 && !shareMountFlag

  const qc = useQueryClient()
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [inited, setInited] = useState(false)
  const [archivesExpanded, setArchivesExpanded] = useState(false)
  const [archivesInited, setArchivesInited] = useState(false)
  const [renameTarget, setRenameTarget] = useState<string | null>(null)

  const { data: me } = useQuery({
    ...meQuery(),
    enabled: !isShare,
    staleTime: 60 * 1000,
    gcTime: 5 * 60 * 1000,
  })

  const userId = me?.id ?? null
  const userName = me?.name ?? null
  const { activeWorkspaceId, activeWorkspace } = useAuthContext()
  const workspaceStorageKey = activeWorkspaceId ?? 'default'
  const workspaceSlug = activeWorkspace?.slug ?? userName ?? null

  const filterByWorkspace = useCallback(
    (items: DbDoc[]) => {
      if (!activeWorkspaceId) return items
      return items.filter((doc) => {
        const owner = doc.workspace_id ?? doc.owner_id
        if (!owner) {
          // Backend might omit workspace_id for older records; assume active workspace
          return true
        }
        return owner === activeWorkspaceId
      })
    },
    [activeWorkspaceId],
  )

  useEffect(() => {
    if (typeof window === 'undefined') return
    const key = `file-tree-expanded-${userId || 'default'}-${workspaceStorageKey}`
    try {
      const saved = localStorage.getItem(key)
      if (saved) {
        const parsed = JSON.parse(saved)
        if (Array.isArray(parsed)) setExpanded(new Set(parsed))
      }
    } catch {
      /* noop */
    }
    setInited(true)
  }, [userId, workspaceStorageKey])

  useEffect(() => {
    if (!inited) return
    const key = `file-tree-expanded-${userId || 'default'}-${workspaceStorageKey}`
    try {
      localStorage.setItem(key, JSON.stringify(Array.from(expanded)))
    } catch {
      /* noop */
    }
  }, [expanded, inited, userId, workspaceStorageKey])

  const archivesStorageKey = `file-tree-archives-${userId || 'default'}-${workspaceStorageKey}`

  useEffect(() => {
    if (typeof window === 'undefined') return
    try {
      const saved = localStorage.getItem(archivesStorageKey)
      if (saved != null) setArchivesExpanded(saved === '1')
    } catch {
      /* noop */
    }
    setArchivesInited(true)
  }, [archivesStorageKey])

  useEffect(() => {
    if (!archivesInited) return
    if (typeof window === 'undefined') return
    try {
      localStorage.setItem(archivesStorageKey, archivesExpanded ? '1' : '0')
    } catch {
      /* noop */
    }
  }, [archivesExpanded, archivesInited, archivesStorageKey])

  const { data: documentsUser = [], isLoading: isLoadingUser } = useQuery({
    queryKey: ['documents', userId, workspaceStorageKey, 'active'],
    enabled: !!userId && !!activeWorkspaceId && !isShare,
    queryFn: async () => {
      const res = await listDocuments({ state: 'active' })
      const items = (res.items ?? []) as unknown as DbDoc[]
      return filterByWorkspace(items)
    },
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  })

  const { data: shareMounts = [] } = useShareMounts({ enabled: !!userId && !!activeWorkspaceId && !isShare })
  const shareMountTrees = useQueries({
    queries: (shareMounts as any[]).map((mount) => ({
      queryKey: ['share-mount-tree', mount.id, mount.token],
      enabled: !!activeWorkspaceId && !isShare,
      staleTime: 5 * 60 * 1000,
      gcTime: 10 * 60 * 1000,
      queryFn: async () => await browseShare(mount.token),
    })),
  })

  const shareMountDocuments = useMemo<DbDoc[]>(() => {
    if (isShare || !activeWorkspaceId) return []
    const list: DbDoc[] = []
    shareMounts.forEach((mount: any, idx: number) => {
      const tree = shareMountTrees[idx]?.data?.tree
      if (!tree) return
      const idMap = new Map<string, string>()
      const makeId = (id: string) => `share:${mount.id}:${id}`
      tree.forEach((item: any) => {
        idMap.set(item.id, makeId(item.id))
      })
      tree.forEach((item: any) => {
        const mappedId = idMap.get(item.id) || makeId(item.id)
        const mappedParent =
          item.parent_id && idMap.has(item.parent_id)
            ? idMap.get(item.parent_id)!
            : mount.parent_folder_id ?? null
        list.push({
          id: mappedId,
          source_id: item.id,
          title: item.title,
          parent_id: mappedParent,
          created_at: item.created_at,
          updated_at: item.updated_at,
          type: item.type === 'folder' ? 'folder' : 'document',
          share_token: mount.token,
          is_share_mount: true,
          share_mount_id: mount.id,
          owner_id: activeWorkspaceId,
          workspace_id: activeWorkspaceId,
        })
      })
    })
    return list
  }, [activeWorkspaceId, isShare, shareMountTrees, shareMounts])

  const documentsUserTree = useMemo(() => buildTree(documentsUser), [documentsUser])

  const activeDocumentInfo = useMemo(() => {
    if (isShare) return new Map<string, { id: string; title: string; type: DocumentNode['type']; parent_id?: string | null }>()
    const map = new Map<string, { id: string; title: string; type: DocumentNode['type']; parent_id?: string | null }>()
    const collect = (nodes: DocumentNode[], parentId: string | null) => {
      for (const node of nodes) {
        map.set(node.id, { id: node.id, title: node.title, type: node.type, parent_id: parentId })
        if (node.children && node.children.length) collect(node.children, node.id)
      }
    }
    collect(documentsUserTree, null)
    return map
  }, [documentsUserTree, isShare])

  const { data: archivedDocumentsRaw = [], isLoading: isLoadingArchived } = useQuery({
    queryKey: ['documents', userId, workspaceStorageKey, 'archived'],
    enabled: !!userId && !!activeWorkspaceId && !isShare,
    queryFn: async () => {
      const res = await listDocuments({ state: 'archived' })
      const items = (res.items ?? []) as unknown as DbDoc[]
      return filterByWorkspace(items)
    },
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  })

  const archivedDocumentsUser = useMemo(
    () => buildTree(archivedDocumentsRaw, { useArchivedParent: true, fallbackInfo: activeDocumentInfo }),
    [archivedDocumentsRaw, activeDocumentInfo],
  )

  const { data: documentsShare = [], isLoading: isLoadingShare } = useQuery({
    queryKey: ['share-documents', shareToken],
    enabled: isShare,
    queryFn: async () => {
      const resp = await browseShare(shareToken)
      const items: DbDoc[] = resp.tree.map((n) => ({
        id: n.id,
        title: n.title,
        parent_id: n.parent_id ?? null,
        created_at: n.created_at,
        updated_at: n.updated_at,
        type: n.type === 'folder' ? ('folder' as const) : ('document' as const),
      }))
      return buildTree(items)
    },
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  })

  const docsWorkspace = useMemo(
    () => buildTree([...documentsUser, ...shareMountDocuments]),
    [documentsUser, shareMountDocuments],
  )

  const docs = isShare ? documentsShare : docsWorkspace
  const archivedDocs = isShare ? [] : archivedDocumentsUser
  const loading =
    isShare
      ? isLoadingShare
      : isLoadingUser || isLoadingArchived || shareMountTrees.some((q) => q.isLoading)

  useEffect(() => {
    if (!archivesExpanded || !archivedDocs.length) return
    setExpanded((prev) => {
      const next = new Set(prev)
      const stack: DocumentNode[] = [...archivedDocs]
      while (stack.length) {
        const node = stack.pop()!
        if (node.type === 'folder') {
          next.add(node.id)
        }
        if (node.children && node.children.length) {
          stack.push(...node.children)
        }
      }
      return next
    })
  }, [archivesExpanded, archivedDocs])

  type ActiveShareItem = {
    document_id: string
    document_type: 'document' | 'folder'
    parent_share_id?: string | null
  }

  const activeSharesKey = [...shareKeys.active(), userId ?? null] as const
  const { data: activeShares = [] } = useQuery({
    queryKey: activeSharesKey,
    enabled: !!userId && !isShare,
    queryFn: async () => await listActiveShares(),
    staleTime: 60 * 1000,
    gcTime: 5 * 60 * 1000,
  })

  const sharedDocIds = useMemo(
    () =>
      new Set<string>(
        (activeShares as any[])
          .filter((s: ActiveShareItem) => s.document_type !== 'folder' && s.parent_share_id == null)
          .map((s: ActiveShareItem) => s.document_id),
      ),
    [activeShares],
  )

  const sharedFolderIds = useMemo(
    () =>
      new Set<string>(
        (activeShares as any[])
          .filter((s: ActiveShareItem) => s.document_type === 'folder')
          .map((s: ActiveShareItem) => s.document_id),
      ),
    [activeShares],
  )

  const inheritedDocIds = useMemo(
    () =>
      new Set<string>(
        (activeShares as any[])
          .filter((s: ActiveShareItem) => s.document_type !== 'folder' && s.parent_share_id != null)
          .map((s: ActiveShareItem) => s.document_id),
      ),
    [activeShares],
  )

  const { data: publicDocs = [] } = useQuery({
    queryKey: ['public-docs', workspaceSlug],
    enabled: !!workspaceSlug && !isShare,
    queryFn: async () => {
      try {
        return await listWorkspacePublicDocuments(workspaceSlug!)
      } catch {
        return []
      }
    },
    staleTime: 60 * 1000,
    gcTime: 5 * 60 * 1000,
  })

  const publicDocIds = useMemo(
    () => new Set<string>((publicDocs as any[]).map((d: any) => d.id)),
    [publicDocs],
  )

  const underSharedFolderDocIds = inheritedDocIds

  const underSharedFolderFolderIds = useMemo(() => {
    const parentMap = new Map<string, string | null>()
    const nodeMap = new Map<string, DocumentNode>()
    const buildMaps = (nodes: DocumentNode[], parent: string | null) => {
      for (const n of nodes) {
        parentMap.set(n.id, parent)
        nodeMap.set(n.id, n)
        if (n.children && n.children.length) buildMaps(n.children, n.id)
      }
    }
    buildMaps(docs, null)
    const result = new Set<string>()
    for (const docId of inheritedDocIds) {
      let current = parentMap.get(docId) || null
      while (current) {
        const node = nodeMap.get(current)
        if (node && node.type === 'folder') result.add(current)
        current = parentMap.get(current) || null
      }
    }
    return result
  }, [docs, inheritedDocIds])

  const toggleFolder = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const expandFolder = useCallback((id: string) => {
    setExpanded((prev) => new Set(prev).add(id))
  }, [])

  const expandParentFolders = useCallback(
    (targetId: string) => {
      const findParents = (nodes: DocumentNode[], id: string, parents: string[] = []): string[] | null => {
        for (const n of nodes) {
          if (n.id === id) return parents
          if (n.children?.length) {
            const result = findParents(n.children, id, [...parents, n.id])
            if (result) return result
          }
        }
        return null
      }
      const parents = findParents(docs, targetId)
      if (parents) {
        setExpanded((prev) => {
          const next = new Set(prev)
          parents.forEach((folderId) => next.add(folderId))
          return next
        })
      }
    },
    [docs],
  )

  const refreshDocuments = useCallback(() => {
    if (isShare) {
      qc.invalidateQueries({ queryKey: ['share-documents', shareToken] })
    } else if (activeWorkspaceId) {
      qc.invalidateQueries({ queryKey: ['documents', userId, activeWorkspaceId, 'active'] })
      qc.invalidateQueries({ queryKey: ['documents', userId, activeWorkspaceId, 'archived'] })
      qc.invalidateQueries({ queryKey: shareMountsQuery().queryKey })
      qc.invalidateQueries({ predicate: (query) => {
        const key = query.queryKey
        return Array.isArray(key) && key[0] === 'share-mount-tree'
      } })
    }
  }, [qc, isShare, shareToken, userId, activeWorkspaceId])

  const updateDocuments = useCallback(
    (nextDocs: DocumentNode[]) => {
      if (isShare) qc.setQueryData(['share-documents', shareToken], nextDocs)
      else if (activeWorkspaceId) qc.setQueryData(['documents', userId, activeWorkspaceId, 'active'], nextDocs)
    },
    [isShare, qc, shareToken, userId, activeWorkspaceId],
  )

  const requestRename = useCallback((id: string) => setRenameTarget(id), [])
  const clearRenameTarget = useCallback(() => setRenameTarget(null), [])

  const value = useMemo<CtxType>(
    () => ({
      documents: docs,
      archivedDocuments: archivedDocs,
      expandedFolders: expanded,
      loading,
      sharedDocIds,
      sharedFolderIds,
      publicDocIds,
      underSharedFolderDocIds,
      underSharedFolderFolderIds,
      isShare,
      shareToken,
      archivesExpanded,
      setArchivesExpanded,
      toggleFolder,
      expandFolder,
      expandParentFolders,
      refreshDocuments,
      updateDocuments,
      requestRename,
      renameTarget,
      clearRenameTarget,
    }),
    [
      clearRenameTarget,
      docs,
      archivedDocs,
      expandFolder,
      expandParentFolders,
      expanded,
      archivesExpanded,
      loading,
      publicDocIds,
      refreshDocuments,
      renameTarget,
      requestRename,
      sharedDocIds,
      sharedFolderIds,
      underSharedFolderDocIds,
      underSharedFolderFolderIds,
      isShare,
      shareToken,
      setArchivesExpanded,
      toggleFolder,
      updateDocuments,
    ],
  )

  return <FileTreeCtx.Provider value={value}>{children}</FileTreeCtx.Provider>
}

export function useFileTree() {
  const ctx = useContext(FileTreeCtx)
  if (!ctx) throw new Error('useFileTree must be used within FileTreeProvider')
  return ctx
}
