import { Link, useNavigate } from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { useWorkspacesData } from '@/entities/workspace'
import { DocumentItem, useDocumentsData } from '@/entities/document'
import { Button } from '@/shared/ui/button'
import { LoadingPlaceholder } from '@/shared/ui/loading-placeholder'

interface DocumentListProps {
  workspaceId: string
}

export function DocumentList({ workspaceId }: DocumentListProps) {
  const navigate = useNavigate()
  const workspaces = useWorkspacesData()
  const documentsData = useDocumentsData()

  if (!workspaces || !documentsData || documentsData.documentsLoading) {
    return (
      <LoadingPlaceholder>Loading documents...</LoadingPlaceholder>
    )
  }

  const { documents } = documentsData
  const workspace = workspaces.find((ws) => ws.workspace.id === workspaceId)?.workspace
  const workspaceDocuments = documents.filter((doc) => doc.workspace_id === workspaceId)

  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <Link to="/workspace/$workspaceId" params={{ workspaceId }}>
          <Button variant="ghost" size="sm">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
        </Link>
        <h1 className="text-2xl font-bold">{workspace?.name}</h1>
      </div>

      {workspaceDocuments.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          No documents yet
        </div>
      ) : (
        <div className="space-y-2">
          {workspaceDocuments.map((doc) => (
            <DocumentItem
              key={doc.id}
              document={doc}
              onClick={() => navigate({ to: '/document/$documentId', params: { documentId: doc.id } })}
            />
          ))}
        </div>
      )}
    </div>
  )
}
