import { useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { documentApi } from '@/shared/api'
import type { DocumentResponse } from '@/shared/api'

export function useDocuments(opts: {
  isAuthenticated: boolean
  isRestoring: boolean
  workspaceId: string | null | undefined
}) {
  const { isAuthenticated, isRestoring, workspaceId } = opts
  const queryClient = useQueryClient()

  const { data: documents = [], isLoading: documentsLoading } = useQuery({
    queryKey: ['documents', workspaceId],
    queryFn: async () => {
      const response = await documentApi.list(workspaceId!, { rootOnly: false })
      return response.documents
    },
    enabled: isAuthenticated && !isRestoring && !!workspaceId,
  })

  const addDocument = useCallback((doc: DocumentResponse) => {
    queryClient.setQueryData<DocumentResponse[]>(
      ['documents', doc.workspace_id],
      (prev) => prev ? [doc, ...prev] : [doc]
    )
  }, [queryClient])

  return { documents, documentsLoading, addDocument }
}
