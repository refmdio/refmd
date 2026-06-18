import { useCallback, useEffect, useMemo, useState } from 'react'
import type * as Y from 'yjs'

export type DocumentCommentReply = {
  id: string
  body: string
  authorId: string | null
  authorName: string | null
  createdAt: string
}

export type DocumentCommentThread = {
  id: string
  marker: string
  quote: string
  startLineNumber: number | null
  endLineNumber: number | null
  startOffset: number | null
  endOffset: number | null
  createdAt: string
  updatedAt: string
  resolvedAt: string | null
  replies: DocumentCommentReply[]
}

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
  userId?: string | null
  userName?: string | null
}

const COMMENTS_MAP_NAME = 'refmd_comments'

export function buildCommentMarker(id: string) {
  return `<!--comment:${id}-->`
}

export function createCommentId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `c_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`
  }
  return `c_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`
}

function createReply(body: string, userId?: string | null, userName?: string | null): DocumentCommentReply {
  return {
    id: createCommentId(),
    body: body.trim(),
    authorId: userId ?? null,
    authorName: userName ?? null,
    createdAt: new Date().toISOString(),
  }
}

function normalizeThread(value: unknown): DocumentCommentThread | null {
  if (!value || typeof value !== 'object') return null
  const raw = value as Partial<DocumentCommentThread>
  if (!raw.id || !raw.marker) return null
  const replies = Array.isArray(raw.replies)
    ? raw.replies
        .filter((reply): reply is DocumentCommentReply => {
          return Boolean(
            reply &&
              typeof reply === 'object' &&
              typeof reply.id === 'string' &&
              typeof reply.body === 'string',
          )
        })
        .map((reply) => ({
          id: reply.id,
          body: reply.body,
          authorId: reply.authorId ?? null,
          authorName: reply.authorName ?? null,
          createdAt: reply.createdAt || raw.createdAt || new Date().toISOString(),
        }))
    : []

  return {
    id: raw.id,
    marker: raw.marker,
    quote: raw.quote ?? '',
    startLineNumber: raw.startLineNumber ?? null,
    endLineNumber: raw.endLineNumber ?? null,
    startOffset: raw.startOffset ?? null,
    endOffset: raw.endOffset ?? null,
    createdAt: raw.createdAt ?? new Date().toISOString(),
    updatedAt: raw.updatedAt ?? raw.createdAt ?? new Date().toISOString(),
    resolvedAt: raw.resolvedAt ?? null,
    replies,
  }
}

function readThreads(map: Y.Map<unknown>) {
  return Array.from(map.values())
    .map(normalizeThread)
    .filter((thread): thread is DocumentCommentThread => Boolean(thread))
    .sort((a, b) => {
      if (!a.resolvedAt && b.resolvedAt) return -1
      if (a.resolvedAt && !b.resolvedAt) return 1
      return a.createdAt.localeCompare(b.createdAt)
    })
}

export function useDocumentComments(doc: Y.Doc, options: UseDocumentCommentsOptions = {}) {
  const map = useMemo(() => doc.getMap<unknown>(COMMENTS_MAP_NAME), [doc])
  const [threads, setThreads] = useState<DocumentCommentThread[]>(() => readThreads(map))

  useEffect(() => {
    const update = () => setThreads(readThreads(map))
    update()
    map.observe(update)
    return () => {
      try {
        map.unobserve(update)
      } catch {
        /* noop */
      }
    }
  }, [map])

  const createThread = useCallback(
    (input: CreateThreadInput) => {
      const body = input.body.trim()
      if (!body) return null
      const now = new Date().toISOString()
      const thread: DocumentCommentThread = {
        id: input.id,
        marker: buildCommentMarker(input.id),
        quote: input.quote,
        startLineNumber: input.startLineNumber ?? null,
        endLineNumber: input.endLineNumber ?? null,
        startOffset: input.startOffset ?? null,
        endOffset: input.endOffset ?? null,
        createdAt: now,
        updatedAt: now,
        resolvedAt: null,
        replies: [createReply(body, options.userId, options.userName)],
      }
      doc.transact(() => map.set(thread.id, thread))
      return thread
    },
    [doc, map, options.userId, options.userName],
  )

  const addReply = useCallback(
    (threadId: string, body: string) => {
      const thread = normalizeThread(map.get(threadId))
      const replyBody = body.trim()
      if (!thread || !replyBody) return null
      const next: DocumentCommentThread = {
        ...thread,
        replies: [...thread.replies, createReply(replyBody, options.userId, options.userName)],
        updatedAt: new Date().toISOString(),
      }
      doc.transact(() => map.set(threadId, next))
      return next
    },
    [doc, map, options.userId, options.userName],
  )

  const setResolved = useCallback(
    (threadId: string, resolved: boolean) => {
      const thread = normalizeThread(map.get(threadId))
      if (!thread) return null
      const next: DocumentCommentThread = {
        ...thread,
        resolvedAt: resolved ? new Date().toISOString() : null,
        updatedAt: new Date().toISOString(),
      }
      doc.transact(() => map.set(threadId, next))
      return next
    },
    [doc, map],
  )

  return {
    threads,
    createThread,
    addReply,
    setResolved,
  }
}
