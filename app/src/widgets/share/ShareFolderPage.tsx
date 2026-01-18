import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { BookmarkPlus, FileText } from 'lucide-react'
import { useCallback, useState } from 'react'
import { toast } from 'sonner'

import { ApiError } from '@/shared/api'
import { Button } from '@/shared/ui/button'

import { createShareMount, shareMountsQuery } from '@/entities/share'

type ShareFolderPageProps = {
  token: string
  title: string
  items: Array<{ id: string; title: string; path?: string; shareToken?: string }>
}

export function ShareFolderPage({ token, title, items }: ShareFolderPageProps) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [saving, setSaving] = useState(false)

  const handleClick = (id: string, docShareToken?: string) => {
    // Use the document's child share token if available, otherwise fall back to folder token
    const tokenToUse = docShareToken ?? token
    // Share key is now managed via ShareContext, no need to preserve URL hash
    navigate({
      to: '/document/$id',
      params: { id },
      search: (prev: { token?: string; shareScope?: 'document' | 'folder' }) => ({
        ...prev,
        token: tokenToUse,
        shareScope: docShareToken ? ('document' as const) : ('folder' as const),
      }),
    })
  }

  const handleSave = useCallback(async () => {
    if (saving) return
    setSaving(true)
    try {
      await createShareMount({ token })
      qc.invalidateQueries({ queryKey: shareMountsQuery().queryKey })
      toast.success('Saved to your workspace')
    } catch (error) {
      const status = error instanceof ApiError ? error.status : (error as any)?.status ?? (error as any)?.cause?.status
      if (status === 401 || status === 403) {
        toast.error('Could not save (auth required or expired). Reload and try again.')
      } else {
        const message = error instanceof Error ? error.message : 'Failed to save share'
        toast.error(message)
      }
    } finally {
      setSaving(false)
    }
  }, [qc, saving, token])

  return (
    <div className="h-full bg-background">
      {/* Desktop */}
      <div className="hidden lg:block h-full overflow-y-auto">
        <div className="max-w-6xl mx-auto px-8 py-12">
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">{title}</h1>
            <p className="text-xl text-gray-600 dark:text-gray-300">Select a document from the list or from the sidebar.</p>
            <div className="mt-4 flex justify-center">
          <Button variant="outline" size="sm" onClick={handleSave} disabled={saving}>
            <BookmarkPlus className="mr-2 h-4 w-4" />
            Save to workspace
          </Button>
            </div>
          </div>

          {items.length > 0 ? (
            <div>
              <h2 className="text-lg font-semibold mb-4">Shared Documents</h2>
              <div className="space-y-3">
                {items.map((doc) => (
                  <div
                    key={doc.id}
                    className="p-4 border rounded-lg hover:bg-accent cursor-pointer transition-colors bg-card"
                    onClick={() => handleClick(doc.id, doc.shareToken)}
                  >
                    <div className="flex items-start gap-3">
                      <FileText className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="font-medium truncate">{doc.title || 'Untitled Document'}</div>
                        {doc.path && doc.path.length > 0 && (
                          <div className="text-xs text-muted-foreground truncate mt-0.5">{doc.path}</div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center">
              <div className="border rounded-lg p-8 bg-card">
                <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground mb-1">No documents in this shared folder</p>
                <p className="text-xs text-muted-foreground">Use the sidebar to navigate other items if available.</p>
              </div>
            </div>
          )}

          <div className="text-sm text-gray-500 dark:text-gray-400 text-center mt-8">
            Shared documents open in read-only mode unless granted access.
          </div>
        </div>
      </div>

      {/* Mobile */}
      <div className="lg:hidden p-4">
        <h1 className="text-2xl font-bold mb-4">{title}</h1>
        <p className="text-gray-600 dark:text-gray-300 mb-6">Select a document to view:</p>
        <Button variant="outline" size="sm" className="mb-4" onClick={handleSave} disabled={saving}>
          <BookmarkPlus className="mr-2 h-4 w-4" />
          Save to workspace
        </Button>
        <div className="border rounded-lg bg-card">
          <div className="p-4">
            {items.length > 0 ? (
              <div className="space-y-2">
                {items.map((doc) => (
                  <div
                    key={doc.id}
                    className="p-3 border rounded hover:bg-accent cursor-pointer transition-colors"
                    onClick={() => handleClick(doc.id, doc.shareToken)}
                  >
                    <div className="flex items-start gap-3">
                      <FileText className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="font-medium truncate">{doc.title || 'Untitled Document'}</div>
                        {doc.path && doc.path.length > 0 && (
                          <div className="text-xs text-muted-foreground truncate mt-0.5">{doc.path}</div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">No documents in this shared folder</p>
              </div>
            )}
          </div>
        </div>
        <p className="text-xs text-muted-foreground text-center mt-4">Shared documents open in read-only mode unless granted access.</p>
      </div>
    </div>
  )
}
