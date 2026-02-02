import { FileText, Folder, Archive } from 'lucide-react'
import type { components } from '@/shared/api'

type DocumentResponse = components['schemas']['DocumentResponse']

interface DocumentItemProps {
  document: DocumentResponse
  onClick?: () => void
}

export function DocumentItem({ document, onClick }: DocumentItemProps) {
  const isFolder = document.doc_type === 'folder'

  return (
    <div
      className="flex items-center gap-3 p-3 rounded-lg hover:bg-accent/50 transition-colors cursor-pointer border"
      onClick={onClick}
    >
      <div className="text-muted-foreground">
        {document.is_archived ? (
          <Archive className="h-5 w-5" />
        ) : isFolder ? (
          <Folder className="h-5 w-5" />
        ) : (
          <FileText className="h-5 w-5" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium truncate">
          {document.title}
          {document.is_encrypted && (
            <span className="ml-2 text-xs text-muted-foreground">(encrypted)</span>
          )}
        </p>
        <p className="text-sm text-muted-foreground">
          Updated {new Date(document.updated_at).toLocaleDateString()}
        </p>
      </div>
      {document.is_archived && (
        <span className="text-xs bg-muted text-muted-foreground px-2 py-1 rounded">
          Archived
        </span>
      )}
    </div>
  )
}
