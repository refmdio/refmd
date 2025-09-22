import { Link } from '@tanstack/react-router'
import { Copy, Trash2, Link as LinkIcon, Folder, FileText, ChevronDown, ChevronRight } from 'lucide-react'
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'

import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'

import { browseShare } from '@/entities/share'

import type { ActiveShareItem } from '@/features/sharing/types'

type FolderShareTreeProps = {
  share: ActiveShareItem
  allShares: ActiveShareItem[]
  siteOrigin: string
  onCopy: (text: string) => void
  onRemove: (token: string) => Promise<void> | void
}

type ShareNode = {
  id: string
  title: string
  type: 'folder' | 'document'
  parent_id?: string | null
}

type TreeNode = ShareNode & {
  children: TreeNode[]
}

const formatDate = (value?: string | null) => {
  if (!value) return ''
  try {
    return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(value))
  } catch {
    return String(value)
  }
}

const formatExpiry = (value?: string | null) => {
  if (!value) return 'No expiry'
  const formatted = formatDate(value)
  return formatted ? `Expires ${formatted}` : `Expires ${value}`
}

export function FolderShareTree({ share, allShares, siteOrigin, onCopy, onRemove }: FolderShareTreeProps) {
  const [expanded, setExpanded] = useState(false)
  const toggle = () => setExpanded((v) => !v)
  const localUrl = `/share/${share.token}`

  return (
    <>
      <Card
        className={`group border-border/70 p-5 shadow-sm transition-all duration-200 hover:-translate-y-1 hover:border-primary/40 ${expanded ? 'border-primary/40' : ''}`}
        onClick={toggle}
      >
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              {expanded ? (
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              )}
              <span className="flex items-center gap-2 text-sm font-medium text-foreground">
                <Folder className="h-4 w-4 text-primary" />
                <span className="truncate">{share.document_title}</span>
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline">{share.permission}</Badge>
              <Badge variant="secondary">Folder</Badge>
              <span>{formatExpiry(share.expires_at)}</span>
            </div>
          </div>
          <div className="flex flex-col gap-3 text-xs text-muted-foreground">
            <div className="break-all">
              <LinkIcon className="mr-1 inline h-3 w-3" />
              {share.url}
            </div>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
            <Button size="sm" variant="outline" asChild className="rounded-full px-4">
              <Link to={localUrl as any}>Open</Link>
            </Button>
            <Button size="sm" variant="outline" className="rounded-full px-3" onClick={() => onCopy(share.url)}>
              <Copy className="h-4 w-4" />
              <span className="ml-1 text-xs">Copy</span>
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
              onClick={() => onRemove(share.token)}
            >
              <Trash2 className="h-4 w-4" />
              <span className="ml-1 text-xs">Remove</span>
            </Button>
          </div>
        </div>
      </Card>
      {expanded && (
        <div className="mt-3 pl-7">
          <FolderShareList
            share={share}
            allShares={allShares}
            siteOrigin={siteOrigin}
            onCopy={onCopy}
            onRemove={onRemove}
          />
        </div>
      )}
    </>
  )
}

function FolderShareList({
  share,
  allShares,
  siteOrigin,
  onCopy,
  onRemove,
}: {
  share: ActiveShareItem
  allShares: ActiveShareItem[]
  siteOrigin: string
  onCopy: (text: string) => void
  onRemove: (token: string) => Promise<void> | void
}) {
  const [loading, setLoading] = useState(true)
  const [docs, setDocs] = useState<ShareNode[]>([])
  const [error, setError] = useState<string | null>(null)
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(() => new Set([share.document_id]))

  const fetchDocs = useCallback(async () => {
    setError(null)
    setLoading(true)
    try {
      const resp = await browseShare(share.token)
      const items = resp.tree.map((n: any) => ({
        id: String(n.id),
        title: String(n.title),
        parent_id: (n.parent_id ?? null) as string | null,
        type: (n.type === 'folder' ? 'folder' : 'document') as 'folder' | 'document',
      }))
      setDocs(items)
    } catch (err) {
      console.error('[visibility] fetch shared docs failed', err)
      setError('Failed to load shared documents')
    } finally {
      setLoading(false)
    }
  }, [share.token])

  useEffect(() => {
    void fetchDocs()
  }, [fetchDocs])

  const folderShareMap = useMemo(() => {
    const m = new Map<string, ActiveShareItem>()
    for (const s of allShares) if (s.document_type === 'folder') m.set(s.document_id, s)
    return m
  }, [allShares])

  const childShareForDoc = useCallback(
    (docId: string) =>
      allShares.find(
        (s) => s.document_type === 'document' && s.document_id === docId && s.parent_share_id === share.id,
      ),
    [allShares, share.id],
  )

  const toggleNode = (id: string) =>
    setExpandedNodes((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const excludeFromShare = async (id: string) => {
    try {
      const childShare = childShareForDoc(id)
      if (!childShare) {
        toast.error('No child share found for this folder')
        return
      }
      await onRemove(childShare.token)
      toast.success('Removed from folder share')
      await fetchDocs()
    } catch (err) {
      console.error('[visibility] exclude share failed', err)
      toast.error('Failed to remove from share')
    }
  }

  const tree = useMemo(() => buildTree(docs), [docs])
  const root = tree.find((node) => node.id === share.document_id) ?? tree[0] ?? null

  const renderNodes = (nodes: TreeNode[], depth: number): React.ReactNode =>
    nodes.map((node) => {
      if (node.type === 'document') {
        const childShare = childShareForDoc(node.id)
        const localUrl = childShare
          ? `/document/${node.id}?token=${childShare.token}`
          : `/document/${node.id}?token=${share.token}`
        const fullUrl = childShare ? childShare.url : `${siteOrigin}${localUrl}`
        return (
          <Card
            key={node.id}
            className="border-border/60 p-4 shadow-sm"
            style={{ marginLeft: `${Math.min(depth, 6) * 16}px` }}
          >
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-3">
                <span className="flex items-center gap-2 text-sm font-medium text-foreground">
                  <FileText className="h-4 w-4 text-primary" />
                  <span className="truncate">{node.title}</span>
                </span>
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant="outline">{childShare ? childShare.permission : share.permission}</Badge>
                  <Badge variant="secondary">Document</Badge>
                  {childShare && <Badge variant="secondary">From folder</Badge>}
                  <span>{formatExpiry(childShare?.expires_at ?? share.expires_at)}</span>
                </div>
              </div>
              <div className="text-xs text-muted-foreground">
                <LinkIcon className="mr-1 inline h-3 w-3" />
                {fullUrl}
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2">
                <Button size="sm" variant="outline" asChild className="rounded-full px-4">
                  <Link to={localUrl as any}>Open</Link>
                </Button>
                <Button size="sm" variant="outline" className="rounded-full px-3" onClick={() => onCopy(fullUrl)}>
                  <Copy className="h-4 w-4" />
                  <span className="ml-1 text-xs">Copy</span>
                </Button>
                {childShare ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
                    onClick={() => onRemove(childShare.token)}
                  >
                    <Trash2 className="h-4 w-4" />
                    <span className="ml-1 text-xs">Remove</span>
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
                    onClick={() => excludeFromShare(node.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                    <span className="ml-1 text-xs">Remove</span>
                  </Button>
                )}
              </div>
            </div>
          </Card>
        )
      }

      if (node.id === share.document_id) {
        return renderNodes(node.children, depth)
      }

      const existingShare = folderShareMap.get(node.id)
      const isExpanded = expandedNodes.has(node.id)
      const Chevron = isExpanded ? ChevronDown : ChevronRight
      const handleRowClick: React.MouseEventHandler<HTMLDivElement> = (event) => {
        event.stopPropagation()
        if (node.children.length > 0) toggleNode(node.id)
      }

      if (existingShare) {
        const localUrl = `/share/${existingShare.token}`
        return (
          <React.Fragment key={node.id}>
            <Card
              className="border-border/60 p-4 shadow-sm transition-colors hover:border-primary/40"
              style={{ marginLeft: `${Math.min(depth, 6) * 16}px` }}
              onClick={handleRowClick}
            >
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <Chevron className="h-4 w-4 text-muted-foreground" />
                  <span className="flex items-center gap-2 text-sm font-medium text-foreground">
                    <Folder className="h-4 w-4 text-primary" />
                    <span className="truncate">{node.title}</span>
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant="outline">{existingShare.permission}</Badge>
                  <Badge variant="secondary">Folder</Badge>
                  <span>{formatExpiry(existingShare.expires_at)}</span>
                </div>
                <div className="text-xs text-muted-foreground">
                  <LinkIcon className="mr-1 inline h-3 w-3" />
                  {existingShare.url}
                </div>
                <div className="flex flex-wrap items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                  <Button size="sm" variant="outline" asChild className="rounded-full px-4">
                    <Link to={localUrl as any}>Open</Link>
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="rounded-full px-3"
                    onClick={() => onCopy(existingShare.url)}
                  >
                    <Copy className="h-4 w-4" />
                    <span className="ml-1 text-xs">Copy</span>
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
                    onClick={() => onRemove(existingShare.token)}
                  >
                    <Trash2 className="h-4 w-4" />
                    <span className="ml-1 text-xs">Remove</span>
                  </Button>
                </div>
              </div>
            </Card>
            {isExpanded && node.children.length > 0 ? (
              <div className="space-y-3">{renderNodes(node.children, depth + 1)}</div>
            ) : null}
          </React.Fragment>
        )
      }

      const isExpandedNode = expandedNodes.has(node.id)
      const RowChevron = isExpandedNode ? ChevronDown : ChevronRight
      return (
        <React.Fragment key={node.id}>
          <Card
            className="border-border/60 p-4 shadow-sm transition-colors hover:border-primary/40"
            style={{ marginLeft: `${Math.min(depth, 6) * 16}px` }}
            onClick={handleRowClick}
          >
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-3">
                <RowChevron className="h-4 w-4 text-muted-foreground" />
                <span className="flex items-center gap-2 text-sm font-medium text-foreground">
                  <Folder className="h-4 w-4 text-primary" />
                  <span className="truncate">{node.title}</span>
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <Badge variant="secondary">Folder</Badge>
                <Badge variant="outline">Inherited</Badge>
                <span>{formatExpiry(share.expires_at)}</span>
              </div>
              <div className="text-xs text-muted-foreground">
                <LinkIcon className="mr-1 inline h-3 w-3" />
                {share.url}
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                <Button size="sm" variant="outline" asChild className="rounded-full px-4">
                  <Link to={`/share/${share.token}` as any}>Open</Link>
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="rounded-full px-3"
                  onClick={() => onCopy(share.url)}
                >
                  <Copy className="h-4 w-4" />
                  <span className="ml-1 text-xs">Copy</span>
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
                  onClick={() => excludeFromShare(node.id)}
                >
                  <Trash2 className="h-4 w-4" />
                  <span className="ml-1 text-xs">Remove</span>
                </Button>
              </div>
            </div>
          </Card>
          {isExpandedNode && node.children.length > 0 ? (
            <div className="space-y-3">{renderNodes(node.children, depth + 1)}</div>
          ) : null}
        </React.Fragment>
      )
    })

  return (
    <div className="space-y-3">
      {loading && <div className="text-xs text-muted-foreground">Loading shared documents…</div>}
      {error && !loading && <div className="text-xs text-destructive">{error}</div>}
      {!loading && !error && (!root || root.children.length === 0) && (
        <div className="text-xs text-muted-foreground">No items in this folder.</div>
      )}
      {!loading && !error && root && root.children.length > 0 && (
        <div className="space-y-3">{renderNodes(root.children, 0)}</div>
      )}
    </div>
  )
}

function buildTree(nodes: ShareNode[]): TreeNode[] {
  const map = new Map<string, TreeNode>()
  nodes.forEach((node) => {
    map.set(node.id, { ...node, children: [] })
  })

  const roots: TreeNode[] = []
  nodes.forEach((node) => {
    const current = map.get(node.id)!
    const parentId = node.parent_id ?? null
    if (parentId && map.has(parentId)) {
      map.get(parentId)!.children.push(current)
    } else {
      roots.push(current)
    }
  })

  return roots
}

export default FolderShareTree
