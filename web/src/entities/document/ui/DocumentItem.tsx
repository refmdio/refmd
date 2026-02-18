import type { DocumentResponse } from '@/shared/api'
import { DocumentIcon } from './DocumentIcon'

interface DocumentItemProps {
  document: DocumentResponse
  onClick?: () => void
}

export function DocumentItem({ document, onClick }: DocumentItemProps) {
  return (
    <div
      className="flex items-center gap-3 p-3 rounded-lg hover:bg-accent/50 transition-colors cursor-pointer border"
      onClick={onClick}
    >
      <div className="text-muted-foreground">
        <DocumentIcon docType={document.doc_type} isArchived={document.is_archived} />
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
