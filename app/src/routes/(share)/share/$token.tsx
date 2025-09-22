import { createFileRoute, redirect, useNavigate } from '@tanstack/react-router'
import { FileText } from 'lucide-react'

import { browseShare } from '@/entities/share'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

type LoaderData = {
  token: string
  title: string
  items: Array<{ id: string; title: string; path?: string }>
}

export const Route = createFileRoute('/(share)/share/$token')({
  staticData: { layout: 'share' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const token = params.token
    const resp = await browseShare(token)
    const treeData = Array.isArray(resp.tree) ? resp.tree : []
    if (treeData.length === 0) {
      throw new Error('Invalid or expired share link.')
    }
    const root = treeData.find((n: any) => !n.parent_id) ?? treeData[0]
    if (root?.type !== 'folder') {
      throw redirect({ to: '/document/$id', params: { id: String(root.id) }, search: { token } })
    }

    const idMap = new Map(treeData.map((n: any) => [String(n.id), n]))
    const getPath = (nodeId: string): string => {
      const parts: string[] = []
      let cur = idMap.get(nodeId)
      while (cur && cur.parent_id) {
        const parent = idMap.get(String(cur.parent_id))
        if (!parent) break
        if (String(parent.id) === String(root.id)) break
        parts.push(parent.title)
        cur = parent
      }
      return parts.reverse().join('/')
    }

    const documents = treeData
      .filter((n: any) => n.type === 'document')
      .sort((a: any, b: any) => String(a.title).localeCompare(String(b.title)))
      .map((n: any) => ({ id: String(n.id), title: String(n.title ?? 'Untitled Document'), path: getPath(String(n.id)) }))

    return {
      token,
      title: String(root.title ?? 'Shared Folder'),
      items: documents,
    } satisfies LoaderData
  },
  component: ShareEntry,
})


function ShareEntry() {
  const navigate = useNavigate()
  const { token, items, title } = Route.useLoaderData() as LoaderData

  const handleClick = (id: string) => {
    navigate({
      to: '/document/$id',
      params: { id },
      search: (prev: Record<string, unknown>) => ({ ...prev, token }),
    })
  }

  return (
    <div className="h-full bg-background">
      {/* Desktop */}
      <div className="hidden lg:block h-full overflow-y-auto">
        <div className="max-w-6xl mx-auto px-8 py-12">
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">{title}</h1>
            <p className="text-xl text-gray-600 dark:text-gray-300">
              Select a document from the list or from the sidebar.
            </p>
          </div>

          {items.length > 0 ? (
            <div>
              <h2 className="text-lg font-semibold mb-4">Shared Documents</h2>
              <div className="space-y-3">
                {items.map((doc) => (
                  <div
                    key={doc.id}
                    className="p-4 border rounded-lg hover:bg-accent cursor-pointer transition-colors bg-card"
                    onClick={() => handleClick(doc.id)}
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
        <div className="border rounded-lg bg-card">
          <div className="p-4">
            {items.length > 0 ? (
              <div className="space-y-2">
                {items.map((doc) => (
                  <div
                    key={doc.id}
                    className="p-3 border rounded hover:bg-accent cursor-pointer transition-colors"
                    onClick={() => handleClick(doc.id)}
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
                <p className="text-muted-foreground">No documents</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
