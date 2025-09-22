'use client'

import { Link, useSearch } from '@tanstack/react-router'
import { FileText, Folder, NotebookText, ArrowLeft, Loader2, X } from 'lucide-react'
import { useMemo, useState } from 'react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { ScrollArea } from '@/shared/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/shared/ui/tabs'

import { useBacklinks, useOutgoingLinks } from '@/entities/document'

type DocType = 'document' | 'scrap' | 'folder'

interface BacklinksPanelProps {
  documentId: string
  className?: string
  onClose?: () => void
}

interface BacklinkItem {
  document: { id: string; title: string; type: DocType; file_path?: string }
  linkCount: number
  linkType: 'reference' | 'embed' | 'mention'
}

export default function BacklinksPanel({ documentId, className, onClose }: BacklinksPanelProps) {
  const locationSearch = useSearch({ from: '/(app)/document/$id' })
  const { data: backlinksResp, isLoading: loadingBacklinks, error: errorBacklinks } = useBacklinks(documentId)
  const { data: outgoingResp, isLoading: loadingOutgoing, error: errorOutgoing } = useOutgoingLinks(documentId)
  const backlinks = (backlinksResp?.backlinks || []).map((link) => ({
    document: {
      id: link.document_id || '',
      title: link.title || '',
      file_path: link.file_path || undefined,
      type: (link.document_type === 'scrap' ? 'scrap' : (link.document_type === 'folder' ? 'folder' : 'document')) as DocType,
    },
    linkCount: link.link_count || 1,
    linkType: (link.link_type || 'reference') as 'reference' | 'embed' | 'mention',
  })) as BacklinkItem[]
  const outgoingLinks = (outgoingResp?.links || []).map((link) => ({
    document: {
      id: link.document_id || '',
      title: link.title || '',
      file_path: link.file_path || undefined,
      type: (link.document_type === 'scrap' ? 'scrap' : (link.document_type === 'folder' ? 'folder' : 'document')) as DocType,
    },
    linkCount: 1,
    linkType: (link.link_type || 'reference') as 'reference' | 'embed' | 'mention',
  })) as BacklinkItem[]
  const isLoading = loadingBacklinks || loadingOutgoing
  const error = (errorBacklinks as any)?.message || (errorOutgoing as any)?.message || null
  const [activeTab, setActiveTab] = useState<'backlinks' | 'outgoing'>('backlinks')
  const preservedSearch = useMemo(() => ({ ...locationSearch }), [locationSearch])

  const getIcon = (type: DocType) => {
    switch (type) {
      case 'folder': return <Folder className="h-4 w-4" />
      case 'scrap': return <NotebookText className="h-4 w-4" />
      default: return <FileText className="h-4 w-4" />
    }
  }

  const getLinkTypeLabel = (type: string) => {
    switch (type) {
      case 'embed': return 'Embedded'
      case 'mention': return 'Mentioned'
      default: return 'Referenced'
    }
  }

  const formatFilePath = (path?: string) => {
    if (!path) return undefined
    const parts = path.split('/')
    return parts.length > 1 ? parts.slice(1).join('/') : path
  }

  const renderList = (items: BacklinkItem[]) => {
    if (items.length === 0) {
      return (
        <div className="p-4 text-center text-muted-foreground">
          {activeTab === 'backlinks' ? 'No documents link to this document' : 'This document has no outgoing links'}
        </div>
      )
    }
    return (
      <div className="space-y-1 p-2">
        {items.map((item, idx) => (
          <Link
            key={`${item.document.id}-${idx}`}
            to="/document/$id"
            params={{ id: item.document.id }}
            search={() => preservedSearch}
            className="flex items-center gap-2 p-2 rounded-md hover:bg-accent transition-colors"
          >
            <span className="text-muted-foreground">{getIcon(item.document.type)}</span>
            <div className="flex-1 min-w-0">
              <div className="truncate font-medium">{item.document.title}</div>
              {item.document.file_path && (
                <div className="text-xs text-muted-foreground truncate">{formatFilePath(item.document.file_path)}</div>
              )}
              <div className="text-xs text-muted-foreground">
                {getLinkTypeLabel(item.linkType)} • {item.linkCount} {item.linkCount === 1 ? 'link' : 'links'}
              </div>
            </div>
          </Link>
        ))}
      </div>
    )
  }

  return (
    <div className={cn('flex flex-col h-full', className)}>
      <div className="border-b p-3 flex items-center justify-between">
        <h3 className="font-semibold flex items-center gap-2">
          <ArrowLeft className="h-4 w-4" />
          Document Links
        </h3>
        {onClose && (
          <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8">
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)} className="flex-1 flex flex-col">
        <TabsList className="mx-2 mt-2">
          <TabsTrigger value="backlinks" className="flex-1">Backlinks ({backlinks.length})</TabsTrigger>
          <TabsTrigger value="outgoing" className="flex-1">Outgoing ({outgoingLinks.length})</TabsTrigger>
        </TabsList>
        <ScrollArea className="flex-1">
          {isLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : error ? (
            <div className="p-4 text-center text-destructive">{error}</div>
          ) : (
            <>
              <TabsContent value="backlinks" className="m-0">{renderList(backlinks)}</TabsContent>
              <TabsContent value="outgoing" className="m-0">{renderList(outgoingLinks)}</TabsContent>
            </>
          )}
        </ScrollArea>
      </Tabs>
    </div>
  )
}
