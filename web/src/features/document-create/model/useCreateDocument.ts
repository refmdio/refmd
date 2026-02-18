/**
 * Create Document Hook
 *
 * Handles document creation API call and post-creation navigation.
 * Extracted from ui/CreateDocumentDialog to follow FSD model/ui separation.
 */

import { useState, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { documentApi, ApiError } from '@/shared/api'
import type { DocumentResponse } from '@/shared/api'

interface UseCreateDocumentParams {
  workspaceId: string
  onCreated?: (document: DocumentResponse) => void
  onOpenChange: (open: boolean) => void
}

export function useCreateDocument({ workspaceId, onCreated, onOpenChange }: UseCreateDocumentParams) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const create = useCallback(async (title: string): Promise<boolean> => {
    const trimmed = title.trim()
    if (!trimmed) {
      setError('Title is required')
      return false
    }

    setLoading(true)
    setError(null)

    try {
      const doc = await documentApi.create(workspaceId, { title: trimmed })
      onOpenChange(false)
      onCreated?.(doc)
      navigate({ to: '/document/$documentId', params: { documentId: doc.id } })
      return true
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Failed to create document')
      }
      return false
    } finally {
      setLoading(false)
    }
  }, [workspaceId, onCreated, onOpenChange, navigate])

  return { loading, error, create }
}
