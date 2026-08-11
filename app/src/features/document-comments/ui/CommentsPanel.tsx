import {
  CheckCircle2,
  LocateFixed,
  MessageSquare,
  MessageSquareReply,
  RotateCcw,
  Search,
  SendHorizontal,
  Tag,
  X,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Textarea } from '@/shared/ui/textarea'

import type {
  DocumentEditorApi,
  DocumentEditorRange,
  DocumentEditorSelection,
} from '@/features/plugins'

import {
  findCommentThreadRange,
  getLineEndOffset,
} from '../lib/thread-range'
import {
  buildCommentMarker,
  buildCommentMarkerInsertion,
  createCommentId,
  createCommentMarkerId,
  getCommentSubmitAction,
  parseCommentTags,
  sanitizeCommentQuote,
  sanitizeStoredCommentQuote,
  type DocumentCommentThread,
  useDocumentComments,
} from '../model/comments-store'

type CommentsPanelProps = {
  documentId: string
  token?: string | null
  content: string
  editor: DocumentEditorApi | null
  readOnly?: boolean
  userName?: string | null
  composerState?: CommentComposerState
  onComposerStateChange?: (state: CommentComposerState) => void
  className?: string
  activeThreadId?: string | null
  onClose?: () => void
  onRequestEditor?: () => void
  onActiveThreadChange?: (threadId: string | null) => void
  onCommentMetadataChange?: () => void
}

type CommentComposerState = {
  composerOpen: boolean
  newComment: string
  newTags: string
  newTagsOpen: boolean
}

const EMPTY_COMPOSER_STATE: CommentComposerState = {
  composerOpen: false,
  newComment: '',
  newTags: '',
  newTagsOpen: false,
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

function truncateQuote(value: string, knownMarkers: readonly string[] = []) {
  const normalized = sanitizeCommentQuote(value, knownMarkers)
  if (normalized.length <= 180) return normalized
  return `${normalized.slice(0, 177)}...`
}

function getAnchorLabel(
  thread: DocumentCommentThread,
  knownMarkers: readonly string[],
) {
  const quote = truncateQuote(thread.quote, knownMarkers)
  if (quote) return quote
  if (thread.startLineNumber && thread.startColumn) {
    return `L${thread.startLineNumber}:${thread.startColumn}`
  }
  return 'Cursor'
}

function getSelectionLabel(
  selection: DocumentEditorSelection,
  knownMarkers: readonly string[],
) {
  const quote = truncateQuote(selection.text, knownMarkers)
  if (quote) return quote
  return `L${selection.startLineNumber}:${selection.startColumn}`
}

function threadMatchesSearch(
  thread: DocumentCommentThread,
  query: string,
  knownMarkers: readonly string[],
) {
  if (!query) return true
  const haystack = [
    sanitizeCommentQuote(thread.quote, knownMarkers),
    thread.createdByName ?? '',
    ...thread.tags,
    ...thread.replies.flatMap((reply) => [
      reply.body,
      reply.authorName ?? '',
      reply.createdAt,
    ]),
  ]
    .join('\n')
    .toLowerCase()
  return haystack.includes(query)
}

function buildMarkerLineInsertion(
  content: string,
  selection: DocumentEditorSelection,
  editor: DocumentEditorApi,
  markerText: string,
): { range: DocumentEditorRange; text: string } | null {
  let lineNumber = selection.endLineNumber
  // Full-line selections end at column 1 of the next line.
  if (
    selection.endColumn === 1 &&
    selection.endLineNumber > selection.startLineNumber
  ) {
    lineNumber = selection.endLineNumber - 1
  }
  const lineEndOffset = getLineEndOffset(content, lineNumber)
  const range = editor.getRangeFromOffset(lineEndOffset, 0)
  if (!range) return null
  return { range, text: markerText }
}

function validateTags(tags: string[]) {
  return tags.every((tag) => tag.length <= 64)
}

export function CommentsPanel({
  documentId,
  token,
  content,
  editor,
  readOnly = false,
  userName,
  composerState,
  onComposerStateChange,
  className,
  activeThreadId,
  onClose,
  onRequestEditor,
  onActiveThreadChange,
  onCommentMetadataChange,
}: CommentsPanelProps) {
  const {
    threads,
    isLoading,
    isError,
    createThread,
    addReply,
    setResolved,
    setTags,
  } = useDocumentComments({
    documentId,
    token,
    userName,
  })
  const [selection, setSelection] = useState<DocumentEditorSelection | null>(
    null,
  )
  const [localComposerState, setLocalComposerState] =
    useState<CommentComposerState>(EMPTY_COMPOSER_STATE)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [tagFilter, setTagFilter] = useState('')
  const [tagFilterOpen, setTagFilterOpen] = useState(false)
  const [showResolved, setShowResolved] = useState(false)
  const [replyDrafts, setReplyDrafts] = useState<Record<string, string>>({})
  const [tagDrafts, setTagDrafts] = useState<Record<string, string>>({})
  const [creating, setCreating] = useState(false)
  const [activeReplyThreadId, setActiveReplyThreadId] = useState<string | null>(
    null,
  )
  const [localActiveThreadId, setLocalActiveThreadId] = useState<string | null>(
    null,
  )
  const [replyingThreadId, setReplyingThreadId] = useState<string | null>(null)
  const [editingTagsThreadId, setEditingTagsThreadId] = useState<string | null>(
    null,
  )
  const [resolvingThreadId, setResolvingThreadId] = useState<string | null>(
    null,
  )
  const [taggingThreadId, setTaggingThreadId] = useState<string | null>(null)
  const pendingRevealRef = useRef<string | null>(null)
  const threadItemRefs = useRef<Record<string, HTMLElement | null>>({})
  const contentRef = useRef(content)
  const currentComposerState = composerState ?? localComposerState
  const { composerOpen, newComment, newTags, newTagsOpen } =
    currentComposerState
  const effectiveActiveThreadId =
    activeThreadId === undefined ? localActiveThreadId : activeThreadId
  const updateComposerState = useCallback(
    (patch: Partial<CommentComposerState>) => {
      const next = { ...currentComposerState, ...patch }
      if (composerState === undefined) {
        setLocalComposerState(next)
      }
      onComposerStateChange?.(next)
    },
    [composerState, currentComposerState, onComposerStateChange],
  )
  const setActiveThread = useCallback(
    (threadId: string | null) => {
      if (activeThreadId === undefined) {
        setLocalActiveThreadId(threadId)
      }
      onActiveThreadChange?.(threadId)
    },
    [activeThreadId, onActiveThreadChange],
  )

  const openThreads = useMemo(
    () => threads.filter((thread) => !thread.resolvedAt),
    [threads],
  )
  const allTags = useMemo(
    () => Array.from(new Set(threads.flatMap((thread) => thread.tags))).sort(),
    [threads],
  )
  const knownMarkers = useMemo(
    () => threads.map((thread) => thread.marker),
    [threads],
  )
  const normalizedSearch = searchQuery.trim().toLowerCase()
  const normalizedTagFilter = tagFilter.trim()
  const hasSelectedTarget = Boolean(
    selection &&
      !selection.isEmpty &&
      sanitizeCommentQuote(selection.text, knownMarkers),
  )
  const visibleThreads = useMemo(
    () =>
      threads.filter((thread) => {
        if (!showResolved && thread.resolvedAt) return false
        if (
          normalizedTagFilter &&
          !thread.tags.some((tag) => tag === normalizedTagFilter)
        ) {
          return false
        }
        return threadMatchesSearch(thread, normalizedSearch, knownMarkers)
      }),
    [
      knownMarkers,
      normalizedSearch,
      normalizedTagFilter,
      showResolved,
      threads,
    ],
  )
  const commentSubmitAction = getCommentSubmitAction({
    hasEditor: Boolean(editor),
    hasTarget: hasSelectedTarget,
    hasDraft: Boolean(newComment.trim()),
    readOnly,
    creating,
  })
  const canCreateThread = Boolean(editor && !commentSubmitAction.disabled)

  useEffect(() => {
    contentRef.current = content
  }, [content])

  useEffect(() => {
    if (!editor) {
      return
    }
    setSelection(editor.getSelection())
    return editor.onSelectionChange((next) => setSelection(next))
  }, [editor])

  useEffect(() => {
    if (!effectiveActiveThreadId) return
    const activeThread = threads.find(
      (thread) => thread.id === effectiveActiveThreadId,
    )
    if (!activeThread) return
    if (activeThread.resolvedAt) setShowResolved(true)
    if (
      normalizedSearch &&
      !threadMatchesSearch(activeThread, normalizedSearch, knownMarkers)
    ) {
      setSearchQuery('')
      setSearchOpen(false)
    }
    if (
      normalizedTagFilter &&
      !activeThread.tags.some((tag) => tag === normalizedTagFilter)
    ) {
      setTagFilter('')
      setTagFilterOpen(false)
    }
  }, [
    effectiveActiveThreadId,
    knownMarkers,
    normalizedSearch,
    normalizedTagFilter,
    threads,
  ])

  useEffect(() => {
    if (!effectiveActiveThreadId) return
    const node = threadItemRefs.current[effectiveActiveThreadId]
    if (!node) return
    node.scrollIntoView({ block: 'nearest' })
  }, [effectiveActiveThreadId, visibleThreads])

  const revealThread = useCallback(
    (thread: DocumentCommentThread, contentOverride = content) => {
      setActiveThread(thread.id)
      if (!editor) {
        pendingRevealRef.current = thread.id
        onRequestEditor?.()
        return
      }
      const range = findCommentThreadRange(thread, contentOverride, editor)
      if (!range) return
      editor.revealRange(range)
      editor.setSelection(range)
      editor.focus()
      pendingRevealRef.current = null
    },
    [content, editor, onRequestEditor, setActiveThread],
  )

  useEffect(() => {
    if (!editor || !pendingRevealRef.current) return
    const thread = threads.find((item) => item.id === pendingRevealRef.current)
    if (thread) revealThread(thread)
  }, [editor, revealThread, threads])

  const handleCreateThread = useCallback(async () => {
    if (!editor) {
      onRequestEditor?.()
      return
    }
    if (!selection || !hasSelectedTarget || !canCreateThread) return
    const displayQuote = sanitizeCommentQuote(selection.text, knownMarkers)
    if (!displayQuote) return
    const quote = sanitizeStoredCommentQuote(selection.text, knownMarkers)
    const tags = parseCommentTags(newTags)
    if (!validateTags(tags)) {
      toast.error('Tags must be 64 characters or fewer')
      return
    }
    const id = createCommentId()
    const markerId = createCommentMarkerId()
    const marker = buildCommentMarker(markerId)
    const markerText = buildCommentMarkerInsertion(markerId)
    const startOffset = editor.getOffsetFromPosition({
      lineNumber: selection.startLineNumber,
      column: selection.startColumn,
    })
    const endOffset = editor.getOffsetFromPosition({
      lineNumber: selection.endLineNumber,
      column: selection.endColumn,
    })
    const insertion = buildMarkerLineInsertion(
      contentRef.current,
      selection,
      editor,
      markerText,
    )
    if (!insertion) return
    const inserted = editor.applyEdits([
      {
        range: insertion.range,
        text: insertion.text,
        forceMoveMarkers: true,
      },
    ])
    if (!inserted) return
    if (!contentRef.current.includes(marker)) {
      const lineNumber =
        selection.endColumn === 1 &&
        selection.endLineNumber > selection.startLineNumber
          ? selection.endLineNumber - 1
          : selection.endLineNumber
      const insertAt = getLineEndOffset(contentRef.current, lineNumber)
      contentRef.current = [
        contentRef.current.slice(0, insertAt),
        markerText,
        contentRef.current.slice(insertAt),
      ].join('')
    }
    setCreating(true)
    try {
      const thread = await createThread({
        id,
        marker,
        quote,
        body: newComment,
        startLineNumber: selection.startLineNumber,
        startColumn: selection.startColumn,
        endLineNumber: selection.endLineNumber,
        endColumn: selection.endColumn,
        startOffset,
        endOffset,
        tags,
      })
      if (!thread) return
      updateComposerState(EMPTY_COMPOSER_STATE)
      setActiveThread(thread.id)
      onCommentMetadataChange?.()
      const range = findCommentThreadRange(thread, contentRef.current, editor)
      if (range) {
        editor.revealRange(range)
        editor.setSelection({
          startLineNumber: range.endLineNumber,
          startColumn: range.endColumn,
          endLineNumber: range.endLineNumber,
          endColumn: range.endColumn,
        })
        editor.focus()
      }
      window.setTimeout(() => onCommentMetadataChange?.(), 0)
    } catch (error) {
      const markerIndex = contentRef.current.indexOf(marker)
      if (markerIndex >= 0) {
        let start = markerIndex
        let length = marker.length
        if (markerIndex > 0 && contentRef.current[markerIndex - 1] === '\n') {
          start = markerIndex - 1
          length += 1
        } else if (
          markerIndex > 0 &&
          contentRef.current[markerIndex - 1] === '\u200B'
        ) {
          start = markerIndex - 1
          length += 1
        }
        const markerRange = editor.getRangeFromOffset(start, length)
        if (markerRange) {
          editor.applyEdits([
            {
              range: markerRange,
              text: '',
              forceMoveMarkers: true,
            },
          ])
        }
      }
      toast.error('Could not save comment')
    } finally {
      setCreating(false)
    }
  }, [
    canCreateThread,
    createThread,
    editor,
    hasSelectedTarget,
    knownMarkers,
    newComment,
    newTags,
    onRequestEditor,
    onCommentMetadataChange,
    selection,
    setActiveThread,
    updateComposerState,
  ])

  const handleReply = useCallback(
    async (threadId: string) => {
      const body = replyDrafts[threadId] ?? ''
      if (!body.trim()) return
      setReplyingThreadId(threadId)
      try {
        await addReply(threadId, body)
        setReplyDrafts((current) => ({ ...current, [threadId]: '' }))
        setActiveReplyThreadId(null)
        onCommentMetadataChange?.()
      } catch {
        toast.error('Could not save reply')
      } finally {
        setReplyingThreadId(null)
      }
    },
    [addReply, onCommentMetadataChange, replyDrafts],
  )

  const handleSetResolved = useCallback(
    async (threadId: string, resolved: boolean) => {
      setResolvingThreadId(threadId)
      try {
        await setResolved(threadId, resolved)
        onCommentMetadataChange?.()
      } catch {
        toast.error('Could not update comment')
      } finally {
        setResolvingThreadId(null)
      }
    },
    [onCommentMetadataChange, setResolved],
  )

  const handleUpdateTags = useCallback(
    async (threadId: string, value: string) => {
      const tags = parseCommentTags(value)
      if (!validateTags(tags)) {
        toast.error('Tags must be 64 characters or fewer')
        return
      }
      setTaggingThreadId(threadId)
      try {
        await setTags(threadId, tags)
        setEditingTagsThreadId(null)
        setTagDrafts((current) => {
          const next = { ...current }
          delete next[threadId]
          return next
        })
        onCommentMetadataChange?.()
      } catch {
        toast.error('Could not update tags')
      } finally {
        setTaggingThreadId(null)
      }
    },
    [onCommentMetadataChange, setTags],
  )

  const renderThread = (thread: DocumentCommentThread) => {
    const resolved = Boolean(thread.resolvedAt)
    const active = effectiveActiveThreadId === thread.id
    const draft = replyDrafts[thread.id] ?? ''
    const tagDraft = tagDrafts[thread.id] ?? thread.tags.join(', ')
    const markerPresent = content.includes(thread.marker)
    const anchored = thread.anchored && markerPresent
    const editingTags = editingTagsThreadId === thread.id
    const tagDirty =
      parseCommentTags(tagDraft).join(',') !== thread.tags.join(',')
    const replyOpen = activeReplyThreadId === thread.id
    return (
      <article
        key={thread.id}
        ref={(node) => {
          threadItemRefs.current[thread.id] = node
        }}
        className={cn(
          'group relative border-b border-border/50 py-4 pl-5 pr-1 transition-colors last:border-b-0 hover:bg-muted/20',
          active && 'bg-primary/10',
          resolved && 'opacity-70',
        )}
      >
        <span
          className={cn(
            'absolute left-1 top-5 h-2 w-2 rounded-full',
            resolved ? 'bg-muted-foreground/50' : 'bg-primary',
          )}
          title={resolved ? 'Resolved' : 'Open'}
        />
        {!anchored ? (
          <span
            className="absolute left-0 top-9 h-4 w-4 rounded-full border border-destructive/60"
            title="Unlinked"
          />
        ) : null}
        <div className="flex items-start justify-between gap-2">
          <button
            type="button"
            onClick={() => revealThread(thread)}
            className="min-w-0 flex-1 text-left"
          >
            <p className="line-clamp-3 text-sm font-medium leading-5 text-foreground">
              {getAnchorLabel(thread, knownMarkers)}
            </p>
            <time className="mt-1 block truncate text-[11px] text-muted-foreground">
              {formatTimestamp(thread.updatedAt)}
            </time>
          </button>
          <div className="flex shrink-0 items-center gap-0.5 opacity-60 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              title="Tags"
              disabled={readOnly}
              onClick={() => {
                setEditingTagsThreadId((current) =>
                  current === thread.id ? null : thread.id,
                )
                setTagDrafts((current) => ({
                  ...current,
                  [thread.id]: current[thread.id] ?? thread.tags.join(', '),
                }))
              }}
            >
              <Tag className="h-3.5 w-3.5" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              title="Reveal"
              onClick={() => revealThread(thread)}
            >
              <LocateFixed className="h-3.5 w-3.5" />
            </Button>
            {!resolved ? (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                title="Reply"
                disabled={readOnly}
                onClick={() => {
                  setActiveThread(thread.id)
                  setActiveReplyThreadId((current) =>
                    current === thread.id ? null : thread.id,
                  )
                }}
              >
                <MessageSquareReply className="h-3.5 w-3.5" />
              </Button>
            ) : null}
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              title={resolved ? 'Reopen' : 'Resolve'}
              disabled={readOnly || resolvingThreadId === thread.id}
              onClick={() => handleSetResolved(thread.id, !resolved)}
            >
              {resolved ? (
                <RotateCcw className="h-3.5 w-3.5" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5" />
              )}
            </Button>
          </div>
        </div>

        {thread.tags.length ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {thread.tags.map((tag) => (
              <button
                key={tag}
                type="button"
                className="rounded-full border border-border/60 bg-muted/30 px-2 py-0.5 text-[11px] leading-4 text-muted-foreground hover:text-foreground"
                onClick={() => {
                  setTagFilter(tag)
                  setTagFilterOpen(true)
                }}
              >
                {tag}
              </button>
            ))}
          </div>
        ) : null}

        {editingTags ? (
          <div className="mt-3 flex items-center gap-2 rounded-md bg-muted/25 p-2">
            <Input
              value={tagDraft}
              onChange={(event) =>
                setTagDrafts((current) => ({
                  ...current,
                  [thread.id]: event.target.value,
                }))
              }
              onKeyDown={(event) => {
                if (event.key !== 'Enter') return
                event.preventDefault()
                void handleUpdateTags(thread.id, tagDraft)
              }}
              aria-label="Tags"
              className="h-8 border-border/60 bg-background/80 text-xs"
              disabled={readOnly || taggingThreadId === thread.id}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0"
              title="Save"
              disabled={readOnly || taggingThreadId === thread.id || !tagDirty}
              onClick={() => handleUpdateTags(thread.id, tagDraft)}
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        ) : null}

        <div className="mt-3 space-y-3">
          {thread.replies.map((reply) => (
            <div key={reply.id} className="border-l border-border/60 pl-3">
              <div className="mb-1 flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
                <span className="truncate">
                  {reply.authorName || 'Anonymous'}
                </span>
                <time className="shrink-0">
                  {formatTimestamp(reply.createdAt)}
                </time>
              </div>
              <p className="whitespace-pre-wrap break-words text-sm leading-5 text-foreground">
                {reply.body}
              </p>
            </div>
          ))}
        </div>

        {!resolved && replyOpen ? (
          <div className="mt-3 flex items-end gap-2 rounded-md bg-muted/25 p-2">
            <Textarea
              value={draft}
              onChange={(event) =>
                setReplyDrafts((current) => ({
                  ...current,
                  [thread.id]: event.target.value,
                }))
              }
              placeholder="Reply"
              className="min-h-10 flex-1 resize-none border-border/60 bg-background/80 text-sm"
              disabled={readOnly || replyingThreadId === thread.id}
            />
            <Button
              type="button"
              size="icon"
              title="Reply"
              disabled={
                readOnly || replyingThreadId === thread.id || !draft.trim()
              }
              onClick={() => handleReply(thread.id)}
            >
              <SendHorizontal className="h-4 w-4" />
            </Button>
          </div>
        ) : null}
      </article>
    )
  }

  return (
    <aside className={cn('flex h-full min-h-0 flex-col', className)}>
      <div className="shrink-0 border-b border-border/60 pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <MessageSquare className="h-4 w-4 shrink-0 text-primary" />
            <h2 className="truncate text-sm font-semibold text-foreground">
              Comments
            </h2>
            <span className="rounded-full border border-border/60 px-2 py-0.5 text-[11px] tabular-nums text-muted-foreground">
              {openThreads.length}/{threads.length}
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            <Button
              type="button"
              variant={searchOpen || searchQuery ? 'secondary' : 'ghost'}
              size="icon"
              className="h-8 w-8"
              title="Search"
              onClick={() => setSearchOpen((value) => !value)}
            >
              <Search className="h-3.5 w-3.5" />
            </Button>
            <Button
              type="button"
              variant={tagFilterOpen || tagFilter ? 'secondary' : 'ghost'}
              size="icon"
              className="h-8 w-8"
              title="Filter tag"
              onClick={() => setTagFilterOpen((value) => !value)}
            >
              <Tag className="h-3.5 w-3.5" />
            </Button>
            <Button
              type="button"
              variant={showResolved ? 'secondary' : 'ghost'}
              size="icon"
              className="h-8 w-8"
              title="Show resolved"
              onClick={() => setShowResolved((value) => !value)}
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
            </Button>
            {onClose ? (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                title="Close"
                onClick={onClose}
              >
                <X className="h-4 w-4" />
              </Button>
            ) : null}
          </div>
        </div>
        {searchOpen || tagFilterOpen ? (
          <div className="mt-3 grid gap-2">
            {searchOpen ? (
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  aria-label="Search"
                  className="h-8 pl-8 text-xs"
                />
              </div>
            ) : null}
            {tagFilterOpen ? (
              <div className="relative">
                <Tag className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={tagFilter}
                  onChange={(event) => setTagFilter(event.target.value)}
                  aria-label="Filter tag"
                  list={`comment-tags-${documentId}`}
                  className="h-8 pl-8 text-xs"
                />
              </div>
            ) : null}
            <datalist id={`comment-tags-${documentId}`}>
              {allTags.map((tag) => (
                <option key={tag} value={tag} />
              ))}
            </datalist>
          </div>
        ) : null}
      </div>

      <div className="shrink-0 border-b border-border/60 py-3">
        {!composerOpen && !newComment ? (
          <button
            type="button"
            className="flex h-10 w-full items-center justify-between rounded-md border border-border/60 bg-background/50 px-3 text-left text-sm text-muted-foreground transition-colors hover:border-primary/30 hover:bg-muted/30"
            disabled={readOnly}
            onClick={() => updateComposerState({ composerOpen: true })}
          >
            <span>Add comment</span>
            <SendHorizontal className="h-3.5 w-3.5" />
          </button>
        ) : (
          <div className="rounded-md border border-border/60 bg-background/60 focus-within:border-primary/40">
            <Textarea
              value={newComment}
              onChange={(event) =>
                updateComposerState({ newComment: event.target.value })
              }
              autoFocus
              placeholder="Add comment"
              className="min-h-20 resize-none border-0 bg-transparent px-3 py-3 text-sm shadow-none focus-visible:ring-0"
              disabled={readOnly}
            />
            {newTagsOpen ? (
              <div className="border-t border-border/50 px-3 py-2">
                <div className="relative">
                  <Tag className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={newTags}
                    onChange={(event) =>
                      updateComposerState({ newTags: event.target.value })
                    }
                    aria-label="Tags"
                    className="h-8 border-border/60 bg-background/80 pl-8 text-xs"
                    disabled={readOnly}
                  />
                </div>
              </div>
            ) : null}
            <div className="flex items-center justify-between gap-2 border-t border-border/50 px-2 py-2">
              <button
                type="button"
                className="min-w-0 rounded px-2 py-1 text-left text-xs text-muted-foreground hover:bg-muted/50"
                onClick={onRequestEditor}
                title={
                  hasSelectedTarget && selection
                    ? getSelectionLabel(selection, knownMarkers)
                    : 'Open editor'
                }
              >
                <span className="line-clamp-1">
                  {hasSelectedTarget && selection
                    ? getSelectionLabel(selection, knownMarkers)
                    : 'Editor'}
                </span>
              </button>
              <div className="flex shrink-0 items-center gap-1">
                <Button
                  type="button"
                  variant={newTagsOpen || newTags ? 'secondary' : 'ghost'}
                  size="icon"
                  className="h-8 w-8"
                  title="Tags"
                  disabled={readOnly}
                  onClick={() =>
                    updateComposerState({ newTagsOpen: !newTagsOpen })
                  }
                >
                  <Tag className="h-3.5 w-3.5" />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  title="Cancel"
                  onClick={() => {
                    updateComposerState(EMPTY_COMPOSER_STATE)
                  }}
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
                <Button
                  type="button"
                  size="icon"
                  className="h-8 w-8"
                  disabled={commentSubmitAction.disabled}
                  title={commentSubmitAction.title}
                  onClick={handleCreateThread}
                >
                  <SendHorizontal className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto py-1">
        {isLoading ? (
          <div className="flex h-full min-h-40 items-center justify-center text-sm text-muted-foreground">
            Loading comments
          </div>
        ) : isError ? (
          <div className="flex h-full min-h-40 items-center justify-center text-sm text-muted-foreground">
            Could not load comments
          </div>
        ) : visibleThreads.length ? (
          <div>{visibleThreads.map(renderThread)}</div>
        ) : (
          <div className="flex h-full min-h-40 items-center justify-center text-sm text-muted-foreground">
            {threads.length ? 'No matching comments' : 'No comments'}
          </div>
        )}
      </div>
    </aside>
  )
}

export default CommentsPanel
