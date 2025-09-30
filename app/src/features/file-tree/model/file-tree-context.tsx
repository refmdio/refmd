import { useQuery, useQueryClient } from '@tanstack/react-query'
import React, { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react'

import { useShareToken } from '@/shared/contexts/share-token-context'

import { listDocuments } from '@/entities/document'
import { listUserPublicDocuments } from '@/entities/public'
import { browseShare, listActiveShares, shareKeys } from '@/entities/share'
import { meQuery } from '@/entities/user'

import type { DocumentNode } from '@/features/file-tree/model/types'

type CtxType = {
  documents: DocumentNode[]
  expandedFolders: Set<string>
  loading: boolean
  sharedDocIds: Set<string>
  sharedFolderIds: Set<string>
  publicDocIds: Set<string>
  underSharedFolderDocIds: Set<string>
  underSharedFolderFolderIds: Set<string>
  shareToken: string
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
  title: string
  parent_id?: string | null
  created_at: string
  updated_at: string
  type?: 'document' | 'folder'
}

function buildTree(docs: DbDoc[]): DocumentNode[] {
  const nodeMap = new Map<string, DocumentNode>()
  docs.forEach((d) => {
    const type: DocumentNode['type'] = d.type === 'folder' ? 'folder' : 'file'
    nodeMap.set(d.id, {
      id: d.id,
      title: d.title,
      type,
      children: [],
      created_at: d.created_at,
      updated_at: d.updated_at,
    })
  })
  const roots: DocumentNode[] = []
  docs.forEach((d) => {
    const node = nodeMap.get(d.id)!
    const pid = d.parent_id ?? undefined
    if (pid && nodeMap.has(pid)) {
      const parent = nodeMap.get(pid)!
      parent.children!.push(node)
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
  const isShare = shareToken.length > 0

  const qc = useQueryClient()
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [inited, setInited] = useState(false)
  const [renameTarget, setRenameTarget] = useState<string | null>(null)

  const { data: me } = useQuery({
    ...meQuery(),
    enabled: !isShare,
    staleTime: 60 * 1000,
    gcTime: 5 * 60 * 1000,
  })

  const userId = me?.id ?? null
  const userName = me?.name ?? null

  useEffect(() => {
    if (typeof window === 'undefined') return
    const key = `file-tree-expanded-${userId || 'default'}`
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
  }, [userId])

  useEffect(() => {
    if (!inited) return
    const key = `file-tree-expanded-${userId || 'default'}`
    try {
      localStorage.setItem(key, JSON.stringify(Array.from(expanded)))
    } catch {
      /* noop */
    }
  }, [expanded, inited, userId])

  const { data: documentsUser = [], isLoading: isLoadingUser } = useQuery({
    queryKey: ['documents', userId],
    enabled: !!userId && !isShare,
    queryFn: async () => {
      const res = await listDocuments({})
      const items = (res.items ?? []) as unknown as DbDoc[]
      return buildTree(items)
    },
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  })

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

  const docs = isShare ? documentsShare : documentsUser
  const loading = isShare ? isLoadingShare : isLoadingUser

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
    queryKey: ['public-docs', userName],
    enabled: !!userName && !isShare,
    queryFn: async () => {
      try {
        return await listUserPublicDocuments(userName!)
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
    } else {
      qc.invalidateQueries({ queryKey: ['documents', userId] })
    }
  }, [qc, isShare, shareToken, userId])

  const updateDocuments = useCallback(
    (nextDocs: DocumentNode[]) => {
      if (isShare) qc.setQueryData(['share-documents', shareToken], nextDocs)
      else qc.setQueryData(['documents', userId], nextDocs)
    },
    [isShare, qc, shareToken, userId],
  )

  const requestRename = useCallback((id: string) => setRenameTarget(id), [])
  const clearRenameTarget = useCallback(() => setRenameTarget(null), [])

  const value = useMemo<CtxType>(
    () => ({
      documents: docs,
      expandedFolders: expanded,
      loading,
      sharedDocIds,
      sharedFolderIds,
      publicDocIds,
      underSharedFolderDocIds,
      underSharedFolderFolderIds,
      shareToken,
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
      expandFolder,
      expandParentFolders,
      expanded,
      loading,
      publicDocIds,
      refreshDocuments,
      renameTarget,
      requestRename,
      sharedDocIds,
      sharedFolderIds,
      underSharedFolderDocIds,
      underSharedFolderFolderIds,
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
