import { Link, useParams } from '@tanstack/react-router'
import { FileText, Folder, Archive } from 'lucide-react'
import { ScrollArea } from '@/shared/ui/scroll-area'
import type { components } from '@/shared/api'

type DocumentResponse = components['schemas']['DocumentResponse']

interface DocumentTreeProps {
  documents: DocumentResponse[]
  loading?: boolean
}

export function DocumentTree({ documents, loading }: DocumentTreeProps) {
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
          />
        ))}
      </div>
    </ScrollArea>
  )
}

interface DocumentTreeItemProps {
  document: DocumentResponse
  isActive: boolean
}

function DocumentTreeItem({ document, isActive }: DocumentTreeItemProps) {
  const isFolder = document.doc_type === 'folder'

  return (
    <Link
      to="/document/$documentId"
      params={{ documentId: document.id }}
      className={`flex items-center gap-1.5 mx-3 px-3 py-1.5 text-xs rounded-md hover:bg-sidebar-accent transition-colors ${
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
    </Link>
  )
}
