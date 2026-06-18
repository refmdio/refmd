import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'

import {
  createDocumentCommentReply,
  createDocumentCommentThread,
  documentCommentsQuery,
  documentKeys,
  updateDocumentCommentThread,
  type DocumentCommentReply,
  type DocumentCommentsResponse,
  type DocumentCommentThread,
} from '@/entities/document'

export type { DocumentCommentReply, DocumentCommentThread }

type CreateThreadInput = {
  id: string
  quote: string
  body: string
  startLineNumber?: number | null
  endLineNumber?: number | null
  startOffset?: number | null
  endOffset?: number | null
}

type UseDocumentCommentsOptions = {
  documentId: string
  token?: string | null
  userName?: string | null
}

export function buildCommentMarker(id: string) {
  return `<!--comment:${id}-->`
}

function fallbackUuid() {
  const bytes = new Uint8Array(16)
  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.getRandomValues === 'function'
  ) {
    crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256)
    }
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function createCommentId() {
  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.randomUUID === 'function'
  ) {
    return crypto.randomUUID()
  }
  return fallbackUuid()
}

function sortThreads(threads: DocumentCommentThread[]) {
  return [...threads].sort((a, b) => {
    if (!a.resolvedAt && b.resolvedAt) return -1
    if (a.resolvedAt && !b.resolvedAt) return 1
    return a.createdAt.localeCompare(b.createdAt)
  })
}

export function useDocumentComments({
  documentId,
  token,
  userName,
}: UseDocumentCommentsOptions) {
  const queryClient = useQueryClient()
  const query = useQuery(documentCommentsQuery(documentId, { token }))
  const queryKey = documentKeys.comments(documentId, token)

  const setThreads = useCallback(
    (
      updater: (threads: DocumentCommentThread[]) => DocumentCommentThread[],
    ) => {
      queryClient.setQueryData<DocumentCommentsResponse>(
        queryKey,
        (current) => {
          const currentThreads = current?.threads ?? []
          return { threads: sortThreads(updater(currentThreads)) }
        },
      )
    },
    [queryClient, queryKey],
  )

  const createThreadMutation = useMutation({
    mutationFn: (input: CreateThreadInput) =>
      createDocumentCommentThread({
        documentId,
        token,
        id: input.id,
        marker: buildCommentMarker(input.id),
        quote: input.quote,
        body: input.body,
        startLineNumber: input.startLineNumber ?? null,
        endLineNumber: input.endLineNumber ?? null,
        startOffset: input.startOffset ?? null,
        endOffset: input.endOffset ?? null,
        authorName: userName ?? null,
      }),
    onSuccess: (thread) => {
      setThreads((threads) => [
        ...threads.filter((item) => item.id !== thread.id),
        thread,
      ])
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey })
    },
  })

  const addReplyMutation = useMutation({
    mutationFn: ({ threadId, body }: { threadId: string; body: string }) =>
      createDocumentCommentReply({
        documentId,
        threadId,
        token,
        body,
        authorName: userName ?? null,
      }),
    onSuccess: (reply, variables) => {
      setThreads((threads) =>
        threads.map((thread) =>
          thread.id === variables.threadId
            ? {
                ...thread,
                updatedAt: reply.createdAt,
                replies: [
                  ...thread.replies.filter((item) => item.id !== reply.id),
                  reply,
                ],
              }
            : thread,
        ),
      )
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey })
    },
  })

  const setResolvedMutation = useMutation({
    mutationFn: ({
      threadId,
      resolved,
    }: {
      threadId: string
      resolved: boolean
    }) =>
      updateDocumentCommentThread({
        documentId,
        threadId,
        token,
        resolved,
      }),
    onSuccess: (thread) => {
      setThreads((threads) =>
        threads.map((item) => (item.id === thread.id ? thread : item)),
      )
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey })
    },
  })

  const createThread = useCallback(
    async (input: CreateThreadInput) => {
      if (!input.body.trim()) return null
      return createThreadMutation.mutateAsync(input)
    },
    [createThreadMutation],
  )

  const addReply = useCallback(
    async (threadId: string, body: string) => {
      if (!body.trim()) return null
      return addReplyMutation.mutateAsync({ threadId, body })
    },
    [addReplyMutation],
  )

  const setResolved = useCallback(
    async (threadId: string, resolved: boolean) => {
      return setResolvedMutation.mutateAsync({ threadId, resolved })
    },
    [setResolvedMutation],
  )

  return {
    threads: query.data?.threads ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
    isSaving:
      createThreadMutation.isPending ||
      addReplyMutation.isPending ||
      setResolvedMutation.isPending,
    createThread,
    addReply,
    setResolved,
  }
}
