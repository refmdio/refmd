import { useState, useEffect } from 'react'
import { Link } from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { workspaceApi, documentApi, ApiError } from '@/shared/api'
import { DocumentItem } from '@/entities/document/ui/DocumentItem'
import { Button } from '@/shared/ui/button'
import type { components } from '@/shared/api'

type DocumentResponse = components['schemas']['DocumentResponse']
type WorkspaceResponse = components['schemas']['WorkspaceResponse']

interface DocumentListProps {
  workspaceId: string
}

export function DocumentList({ workspaceId }: DocumentListProps) {
  const [workspace, setWorkspace] = useState<WorkspaceResponse | null>(null)
  const [documents, setDocuments] = useState<DocumentResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchData() {
      try {
        const [workspaceRes, docsRes] = await Promise.all([
          workspaceApi.get(workspaceId),
          documentApi.list(workspaceId),
        ])
        setWorkspace(workspaceRes.workspace)
        setDocuments(docsRes.documents)
      } catch (err) {
        if (err instanceof ApiError) {
          setError(err.message)
        } else {
          setError('Failed to load documents')
        }
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [workspaceId])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-muted-foreground">Loading documents...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-4 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
        {error}
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <Link to="/dashboard">
          <Button variant="ghost" size="sm">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
        </Link>
        <h1 className="text-2xl font-bold">{workspace?.name}</h1>
      </div>

      {documents.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          No documents yet
        </div>
      ) : (
        <div className="space-y-2">
          {documents.map((doc) => (
            <DocumentItem key={doc.id} document={doc} />
          ))}
        </div>
      )}
    </div>
  )
}
