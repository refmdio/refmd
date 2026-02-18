import { MoreHorizontal, PanelRight } from 'lucide-react'
import { DocumentIcon } from '@/entities/document'
import { ScrollArea } from '@/shared/ui/scroll-area'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'
import type { DocumentResponse } from '@/shared/api'

interface DocumentTreeProps {
  documents: DocumentResponse[]
  loading?: boolean
  currentDocumentId?: string
  onSelectDocument: (doc: DocumentResponse) => void
  onOpenInNewTile?: (doc: DocumentResponse) => void
}

export function DocumentTree({
  documents,
  loading,
  currentDocumentId,
  onSelectDocument,
  onOpenInNewTile,
}: DocumentTreeProps) {

  if (loading) {
    return (
      <div className="px-3 py-2 text-sm text-muted-foreground">Loading documents...</div>
    )
  }

  if (documents.length === 0) {
    return (
      <div className="px-3 py-2 text-sm text-muted-foreground">No documents</div>
    )
  }

  return (
    <ScrollArea className="flex-1">
      <div className="py-1 space-y-1">
        {documents.map((doc) => (
          <DocumentTreeItem
            key={doc.id}
            document={doc}
            isActive={doc.id === currentDocumentId}
            onSelect={() => onSelectDocument(doc)}
            onOpenInNewTile={onOpenInNewTile ? () => onOpenInNewTile(doc) : undefined}
          />
        ))}
      </div>
    </ScrollArea>
  )
}

interface DocumentTreeItemProps {
  document: DocumentResponse
  isActive: boolean
  onSelect: () => void
  onOpenInNewTile?: () => void
}

function DocumentTreeItem({
  document,
  isActive,
  onSelect,
  onOpenInNewTile,
}: DocumentTreeItemProps) {
  return (
    <div
      className={`group flex items-center mx-3 px-3 py-1.5 text-xs rounded-md hover:bg-sidebar-accent transition-colors ${
        isActive ? 'bg-sidebar-accent text-sidebar-foreground' : 'text-sidebar-foreground/70'
      }`}
    >
      <button
        type="button"
        onClick={onSelect}
        className="flex items-center gap-1.5 flex-1 min-w-0 text-left"
      >
        <span className="shrink-0">
          <DocumentIcon docType={document.doc_type} isArchived={document.is_archived} className="h-4 w-4" />
        </span>
        <span className="truncate">{document.title}</span>
      </button>

      {onOpenInNewTile && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="shrink-0 p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-sidebar-accent-foreground/10 transition-opacity"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreHorizontal className="h-3.5 w-3.5" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem onClick={onOpenInNewTile}>
              <PanelRight className="h-4 w-4 mr-2" />
              Open in new tile
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )}
    </div>
  )
}
