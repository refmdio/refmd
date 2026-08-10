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
  marker: string
  quote: string
  body: string
  startLineNumber?: number | null
  startColumn?: number | null
  endLineNumber?: number | null
  endColumn?: number | null
  startOffset?: number | null
  endOffset?: number | null
  tags?: string[]
}

type UpdateThreadInput = {
  threadId: string
  marker?: string
  resolved?: boolean
  tags?: string[]
  anchored?: boolean
}

type UseDocumentCommentsOptions = {
  documentId: string
  token?: string | null
  userName?: string | null
}

type CommentSubmitActionInput = {
  hasEditor: boolean
  hasTarget: boolean
  hasDraft: boolean
  readOnly: boolean
  creating: boolean
}

export function getCommentSubmitAction(input: CommentSubmitActionInput) {
  const label = input.hasEditor ? 'Comment' : 'Open editor'
  return {
    label,
    title: label,
    disabled: input.hasEditor
      ? !input.hasTarget || !input.hasDraft || input.readOnly || input.creating
      : input.readOnly,
  }
}

export function buildCommentMarker(id: string) {
  return `<!--comment:${id}-->`
}

export function parseCommentMarkerId(marker: string) {
  const match = /^<!--comment:([A-Za-z0-9_-]+)-->$/.exec(marker)
  return match?.[1] ?? null
}

const COMMENT_MARKER_PATTERN = /<!--comment:[A-Za-z0-9_-]+-->/g

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function findCommentMarkers(content: string) {
  const matches = content.match(COMMENT_MARKER_PATTERN)
  return matches ? Array.from(new Set(matches)) : []
}

export function findUnknownCommentMarkers(
  content: string,
  knownMarkers: readonly string[],
) {
  const known = new Set(knownMarkers)
  return findCommentMarkers(content).filter((marker) => !known.has(marker))
}

export function stripCommentMarkers(
  content: string,
  markers: readonly string[],
) {
  let out = content
  const seen = new Set<string>()
  for (const marker of markers) {
    if (!marker || seen.has(marker)) continue
    seen.add(marker)
    const escaped = escapeRegExp(marker)
    // Drop markers that occupy a whole line so we don't leave a blank line.
    out = out.replace(new RegExp(`\\n${escaped}(?=\\n|$)`, 'g'), '')
    out = out.replace(new RegExp(`^${escaped}\\n`), '')
    out = out.replace(new RegExp(`^${escaped}$`), '')
    out = out.split(marker).join('')
  }
  return out
}

export function sanitizeCommentQuote(
  quote: string,
  knownMarkers: readonly string[],
) {
  return stripCommentMarkers(quote, knownMarkers).replace(/\s+/g, ' ').trim()
}

export function sanitizeStoredCommentQuote(
  quote: string,
  knownMarkers: readonly string[],
) {
  return stripCommentMarkers(quote, knownMarkers)
}

export function parseCommentTags(value: string) {
  const tags: string[] = []
  for (const part of value.split(',')) {
    const tag = part.trim()
    if (!tag || tags.includes(tag)) continue
    tags.push(tag)
  }
  return tags
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

const COMMENT_MARKER_ID_ALPHABET =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

export function createCommentMarkerId(length = 10) {
  const size = Math.max(6, Math.min(24, Math.floor(length)))
  const bytes = new Uint8Array(size)
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
  return Array.from(
    bytes,
    (byte) =>
      COMMENT_MARKER_ID_ALPHABET[byte % COMMENT_MARKER_ID_ALPHABET.length],
  ).join('')
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
        marker: input.marker,
        quote: input.quote,
        body: input.body,
        startLineNumber: input.startLineNumber ?? null,
        startColumn: input.startColumn ?? null,
        endLineNumber: input.endLineNumber ?? null,
        endColumn: input.endColumn ?? null,
        startOffset: input.startOffset ?? null,
        endOffset: input.endOffset ?? null,
        tags: input.tags ?? [],
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

  const updateThreadMutation = useMutation({
    mutationFn: ({
      threadId,
      marker,
      resolved,
      tags,
      anchored,
    }: UpdateThreadInput) =>
      updateDocumentCommentThread({
        documentId,
        threadId,
        token,
        marker,
        resolved,
        tags,
        anchored,
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
      return updateThreadMutation.mutateAsync({ threadId, resolved })
    },
    [updateThreadMutation],
  )

  const setTags = useCallback(
    async (threadId: string, tags: string[]) => {
      return updateThreadMutation.mutateAsync({ threadId, tags })
    },
    [updateThreadMutation],
  )

  const setAnchored = useCallback(
    async (threadId: string, anchored: boolean) => {
      return updateThreadMutation.mutateAsync({ threadId, anchored })
    },
    [updateThreadMutation],
  )

  return {
    threads: query.data?.threads ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
    isSaving:
      createThreadMutation.isPending ||
      addReplyMutation.isPending ||
      updateThreadMutation.isPending,
    createThread,
    addReply,
    setResolved,
    setTags,
    setAnchored,
  }
}
