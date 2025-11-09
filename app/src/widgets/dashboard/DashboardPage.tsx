import { useSuspenseQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { FileText, Clock } from 'lucide-react'
import { useMemo, useState } from 'react'
import { toast } from 'sonner'

import { listDocumentsQuery, useCreateDocument } from '@/entities/document'
import { meQuery } from '@/entities/user'

type Document = { id: string; title: string; created_at: string; updated_at: string; type?: string | null }

export default function DashboardPage() {
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)
  const { data: me } = useSuspenseQuery(meQuery())
  const { data: list } = useSuspenseQuery(listDocumentsQuery())
  const user = me || { id: '', name: 'User', email: '' }
  const documents = useMemo(() => {
    const items = (list?.items ?? []) as Document[]
    const sorted = items.slice().sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
    return sorted.slice(0, 10)
  }, [list])

  const handleDocumentClick = (doc: Document) => {
    if (!doc.id) return
    navigate({ to: '/document/$id', params: { id: doc.id } })
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    const diffDays = Math.floor(diffHours / 24)
    if (diffHours < 1) return 'Just now'
    if (diffHours < 24) return `${diffHours} hours ago`
    if (diffDays < 7) return `${diffDays} days ago`
    const year = date.getFullYear()
    const month = String(date.getMonth() + 1).padStart(2, '0')
    const day = String(date.getDate()).padStart(2, '0')
    return `${year}/${month}/${day}`
  }

  const createDoc = useCreateDocument()
  const createFirstDocument = async () => {
    setCreating(true)
    try {
      const doc = await createDoc.mutateAsync({ title: 'Untitled', parent_id: null })
      navigate({ to: '/document/$id', params: { id: doc.id } })
      toast.success('Document created')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="h-full overflow-y-auto">
      {/* Desktop */}
      <div className="hidden h-full overflow-y-auto lg:block">
        <div className="mx-auto max-w-2xl px-8 py-12">
          <div className="mb-8 text-center">
            <h1 className="mb-4 text-4xl font-bold text-gray-900 dark:text-white">Welcome back, {user?.name || 'User'}!</h1>
            <p className="text-xl text-gray-600 dark:text-gray-300">
              Select a document from the sidebar or create a new one to get started.
            </p>
          </div>

          {documents.length > 0 ? (
            <div>
              <h2 className="mb-4 text-lg font-semibold">Recent Documents</h2>
              <div className="space-y-3">
                {documents.map((doc) => (
                  <div
                    key={doc.id}
                    className="cursor-pointer rounded-lg border bg-card p-4 transition-colors hover:bg-accent"
                    onClick={() => handleDocumentClick(doc)}
                  >
                    <div className="flex items-start gap-3">
                      <FileText className="h-5 w-5 flex-shrink-0 text-primary" />
                      <div className="min-w-0 flex-1">
                        <div className="font-medium truncate">{doc.title || 'Untitled Document'}</div>
                        <div className="mt-1 flex items-center gap-1 text-sm text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {doc.updated_at && formatDate(doc.updated_at)}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              {documents.length >= 10 && (
                <div className="mt-4 text-center">
                  <p className="text-sm text-muted-foreground">
                    Showing 10 most recent documents. Use the file tree on the left to see all documents.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center">
              <div className="rounded-lg border bg-card p-8">
                <FileText className="mx-auto mb-3 h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground mb-4">No documents yet</p>
                <button
                  className="text-sm text-primary hover:underline disabled:opacity-50"
                  onClick={createFirstDocument}
                  disabled={creating}
                >
                  {creating ? 'Creating…' : 'Create your first document'}
                </button>
              </div>
            </div>
          )}

          <div className="mt-8 text-center text-sm text-gray-500 dark:text-gray-400">
            Your documents are organized in the file tree on the left.
          </div>
        </div>
      </div>

      {/* Mobile */}
      <div className="p-4 lg:hidden">
        <h1 className="mb-4 text-2xl font-bold">Welcome back, {user?.name || 'User'}!</h1>
        <p className="mb-6 text-gray-600 dark:text-gray-300">Select a document to get started:</p>

        <div className="rounded-lg border bg-card">
          <div className="p-4">
            <div className="mb-4 text-sm text-gray-500 dark:text-gray-400">
              Tap the RefMD logo in the top left to access the full file tree, or select a recent document below.
            </div>
            {documents.length > 0 ? (
              <div className="space-y-2">
                {documents.map((doc) => (
                  <div
                    key={doc.id}
                    className="cursor-pointer rounded border p-3 transition-colors hover:bg-accent"
                    onClick={() => handleDocumentClick(doc)}
                  >
                    <div className="flex items-start gap-3">
                      <FileText className="h-5 w-5 flex-shrink-0 text-primary" />
                      <div className="min-w-0 flex-1">
                        <div className="font-medium truncate">{doc.title || 'Untitled Document'}</div>
                        <div className="mt-1 flex items-center gap-1 text-sm text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {doc.updated_at && formatDate(doc.updated_at)}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center">
                <FileText className="mx-auto mb-3 h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground mb-4">No documents yet</p>
                <button
                  className="text-sm text-primary hover:underline disabled:opacity-50"
                  onClick={createFirstDocument}
                  disabled={creating}
                >
                  {creating ? 'Creating…' : 'Create your first document'}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
