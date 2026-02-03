import { useParams } from '@tanstack/react-router'
import { FileText, Folder, Archive } from 'lucide-react'
import { ScrollArea } from '@/shared/ui/scroll-area'
import type { components } from '@/shared/api'

type DocumentResponse = components['schemas']['DocumentResponse']

interface DocumentTreeProps {
  documents: DocumentResponse[]
  loading?: boolean
  onSelectDocument: (doc: DocumentResponse) => void
}

export function DocumentTree({ documents, loading, onSelectDocument }: DocumentTreeProps) {
  const params = useParams({ strict: false })
  const currentDocumentId = params.documentId as string | undefined

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
}

function DocumentTreeItem({ document, isActive, onSelect }: DocumentTreeItemProps) {
  const isFolder = document.doc_type === 'folder'

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex items-center gap-1.5 mx-3 px-3 py-1.5 text-xs rounded-md hover:bg-sidebar-accent transition-colors w-[calc(100%-1.5rem)] text-left ${
        isActive ? 'bg-sidebar-accent text-sidebar-foreground' : 'text-sidebar-foreground/70'
      }`}
    >
      <span className="shrink-0">
        {document.is_archived ? (
          <Archive className="h-4 w-4" />
        ) : isFolder ? (
          <Folder className="h-4 w-4" />
        ) : (
          <FileText className="h-4 w-4" />
        )}
      </span>
      <span className="truncate">{document.title}</span>
    </button>
  )
}
