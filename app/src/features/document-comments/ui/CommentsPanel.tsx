import { CheckCircle2, LocateFixed, MessageSquare, Plus, RotateCcw, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type * as Y from 'yjs'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Textarea } from '@/shared/ui/textarea'

import type { DocumentEditorApi, DocumentEditorRange, DocumentEditorSelection } from '@/features/plugins'

import {
  buildCommentMarker,
  createCommentId,
  type DocumentCommentThread,
  useDocumentComments,
} from '../model/comments-store'

type CommentsPanelProps = {
  doc: Y.Doc
  content: string
  editor: DocumentEditorApi | null
  readOnly?: boolean
  userId?: string | null
  userName?: string | null
  className?: string
  onClose?: () => void
  onRequestEditor?: () => void
}

function formatTimestamp(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function truncateQuote(value: string) {
  const normalized = value.replace(/\s+/g, ' ').trim()
  if (normalized.length <= 180) return normalized
  return `${normalized.slice(0, 177)}...`
}

function findThreadRange(
  thread: DocumentCommentThread,
  content: string,
  editor: DocumentEditorApi,
): DocumentEditorRange | null {
  const markerIndex = content.indexOf(thread.marker)
  if (markerIndex >= 0 && thread.quote) {
    const quoteStart = Math.max(0, markerIndex - thread.quote.length)
    if (content.slice(quoteStart, markerIndex) === thread.quote) {
      return editor.getRangeFromOffset(quoteStart, thread.quote.length)
    }
  }

  if (
    typeof thread.startOffset === 'number' &&
    typeof thread.endOffset === 'number' &&
    thread.endOffset > thread.startOffset
  ) {
    const length = thread.endOffset - thread.startOffset
    return editor.getRangeFromOffset(thread.startOffset, length)
  }

  if (markerIndex >= 0) {
    return editor.getRangeFromOffset(markerIndex, thread.marker.length)
  }

  if (thread.startLineNumber) {
    return {
      startLineNumber: thread.startLineNumber,
      startColumn: 1,
      endLineNumber: thread.endLineNumber ?? thread.startLineNumber,
      endColumn: 1,
    }
  }

  return null
}

function buildMarkerInsertionRange(selection: DocumentEditorSelection): DocumentEditorRange {
  return {
    startLineNumber: selection.endLineNumber,
    startColumn: selection.endColumn,
    endLineNumber: selection.endLineNumber,
    endColumn: selection.endColumn,
  }
}

export function CommentsPanel({
  doc,
  content,
  editor,
  readOnly = false,
  userId,
  userName,
  className,
  onClose,
  onRequestEditor,
}: CommentsPanelProps) {
  const { threads, createThread, addReply, setResolved } = useDocumentComments(doc, { userId, userName })
  const [selection, setSelection] = useState<DocumentEditorSelection | null>(null)
  const [newComment, setNewComment] = useState('')
  const [replyDrafts, setReplyDrafts] = useState<Record<string, string>>({})
  const pendingRevealRef = useRef<string | null>(null)

  const openThreads = useMemo(() => threads.filter((thread) => !thread.resolvedAt), [threads])
  const resolvedThreads = useMemo(() => threads.filter((thread) => thread.resolvedAt), [threads])
  const canCreateThread = Boolean(
    editor &&
      selection &&
      !selection.isEmpty &&
      selection.text.trim().length > 0 &&
      newComment.trim().length > 0 &&
      !readOnly,
  )

  useEffect(() => {
    if (!editor) {
      setSelection(null)
      return
    }
    setSelection(editor.getSelection())
    return editor.onSelectionChange((next) => setSelection(next))
  }, [editor])

  useEffect(() => {
    if (!editor) return
    const decorations = openThreads
      .map((thread) => {
        const range = findThreadRange(thread, content, editor)
        if (!range) return null
        return {
          range,
          inlineClassName: 'refmd-comment-highlight',
          glyphMarginClassName: 'refmd-comment-glyph',
          overviewRulerColor: '#8b5cf6',
          minimapColor: '#8b5cf6',
          hoverMessage: 'Comment',
        }
      })
      .filter((item): item is NonNullable<typeof item> => Boolean(item))

    return editor.setDecorations('core-comments', decorations)
  }, [content, editor, openThreads])

  const revealThread = useCallback(
    (thread: DocumentCommentThread) => {
      if (!editor) {
        pendingRevealRef.current = thread.id
        onRequestEditor?.()
        return
      }
      const range = findThreadRange(thread, content, editor)
      if (!range) return
      editor.revealRange(range)
      editor.setSelection(range)
      editor.focus()
      pendingRevealRef.current = null
    },
    [content, editor, onRequestEditor],
  )

  useEffect(() => {
    if (!editor || !pendingRevealRef.current) return
    const thread = threads.find((item) => item.id === pendingRevealRef.current)
    if (thread) revealThread(thread)
  }, [editor, revealThread, threads])

  const handleCreateThread = useCallback(() => {
    if (!editor || !selection || !canCreateThread) return
    const id = createCommentId()
    const marker = buildCommentMarker(id)
    const startOffset = editor.getOffsetFromPosition({
      lineNumber: selection.startLineNumber,
      column: selection.startColumn,
    })
    const endOffset = editor.getOffsetFromPosition({
      lineNumber: selection.endLineNumber,
      column: selection.endColumn,
    })
    const inserted = editor.applyEdits([
      {
        range: buildMarkerInsertionRange(selection),
        text: marker,
        forceMoveMarkers: true,
      },
    ])
    if (!inserted) return
    const thread = createThread({
      id,
      quote: selection.text,
      body: newComment,
      startLineNumber: selection.startLineNumber,
      endLineNumber: selection.endLineNumber,
      startOffset,
      endOffset,
    })
    if (!thread) return
    setNewComment('')
    revealThread(thread)
  }, [canCreateThread, createThread, editor, newComment, revealThread, selection])

  const handleReply = useCallback(
    (threadId: string) => {
      const body = replyDrafts[threadId] ?? ''
      const next = addReply(threadId, body)
      if (!next) return
      setReplyDrafts((current) => ({ ...current, [threadId]: '' }))
    },
    [addReply, replyDrafts],
  )

  const renderThread = (thread: DocumentCommentThread) => {
    const resolved = Boolean(thread.resolvedAt)
    const draft = replyDrafts[thread.id] ?? ''
    return (
      <article
        key={thread.id}
        className={cn(
          'rounded-md border border-border/60 bg-background/70 p-3 shadow-sm',
          resolved && 'opacity-75',
        )}
      >
        <div className="mb-3 flex items-start justify-between gap-2">
          <button
            type="button"
            onClick={() => revealThread(thread)}
            className="min-w-0 flex-1 text-left"
          >
            <p className="line-clamp-3 text-sm font-medium leading-5 text-foreground">
              {truncateQuote(thread.quote) || 'Untitled anchor'}
            </p>
            <p className="mt-1 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
              {resolved ? 'Resolved' : 'Open'}
            </p>
          </button>
          <div className="flex shrink-0 items-center gap-1">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              title="Reveal"
              onClick={() => revealThread(thread)}
            >
              <LocateFixed className="h-3.5 w-3.5" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              title={resolved ? 'Reopen' : 'Resolve'}
              disabled={readOnly}
              onClick={() => setResolved(thread.id, !resolved)}
            >
              {resolved ? <RotateCcw className="h-3.5 w-3.5" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
            </Button>
          </div>
        </div>

        <div className="space-y-2">
          {thread.replies.map((reply) => (
            <div key={reply.id} className="rounded-md bg-muted/40 px-3 py-2">
              <div className="mb-1 flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
                <span className="truncate">{reply.authorName || 'Anonymous'}</span>
                <time className="shrink-0">{formatTimestamp(reply.createdAt)}</time>
              </div>
              <p className="whitespace-pre-wrap break-words text-sm leading-5 text-foreground">{reply.body}</p>
            </div>
          ))}
        </div>

        {!resolved ? (
          <div className="mt-3 flex items-end gap-2">
            <Textarea
              value={draft}
              onChange={(event) => setReplyDrafts((current) => ({ ...current, [thread.id]: event.target.value }))}
              placeholder="Reply"
              className="min-h-10 flex-1 resize-none text-sm"
              disabled={readOnly}
            />
            <Button
              type="button"
              size="icon"
              title="Reply"
              disabled={readOnly || !draft.trim()}
              onClick={() => handleReply(thread.id)}
            >
              <Plus className="h-4 w-4" />
            </Button>
          </div>
        ) : null}
      </article>
    )
  }

  return (
    <aside className={cn('flex h-full min-h-0 flex-col', className)}>
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-border/60 pb-3">
        <div className="flex min-w-0 items-center gap-2">
          <MessageSquare className="h-4 w-4 shrink-0 text-primary" />
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-foreground">Comments</h2>
            <p className="text-xs text-muted-foreground">
              {openThreads.length} open / {threads.length} total
            </p>
          </div>
        </div>
        {onClose ? (
          <Button type="button" variant="ghost" size="icon" className="h-8 w-8" title="Close" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        ) : null}
      </div>

      <div className="shrink-0 border-b border-border/60 py-3">
        <Textarea
          value={newComment}
          onChange={(event) => setNewComment(event.target.value)}
          placeholder="Comment"
          className="min-h-20 resize-none text-sm"
          disabled={readOnly}
        />
        {selection && !selection.isEmpty && selection.text.trim() ? (
          <p className="mt-2 line-clamp-2 rounded-md bg-muted/40 px-2 py-1 text-xs text-muted-foreground">
            {truncateQuote(selection.text)}
          </p>
        ) : null}
        <div className="mt-2 flex justify-end">
          <Button
            type="button"
            size="sm"
            disabled={!canCreateThread}
            title={editor ? 'Comment' : 'Open editor'}
            onClick={handleCreateThread}
          >
            <Plus className="mr-1.5 h-3.5 w-3.5" />
            Comment
          </Button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto py-3">
        {threads.length ? (
          <div className="space-y-3">
            {openThreads.map(renderThread)}
            {resolvedThreads.length ? (
              <div className="space-y-3 border-t border-border/60 pt-3">
                {resolvedThreads.map(renderThread)}
              </div>
            ) : null}
          </div>
        ) : (
          <div className="flex h-full min-h-40 items-center justify-center text-sm text-muted-foreground">
            No comments
          </div>
        )}
      </div>
    </aside>
  )
}

export default CommentsPanel
