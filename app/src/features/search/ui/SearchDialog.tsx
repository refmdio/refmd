import { useNavigate } from '@tanstack/react-router'
import { FileText, Hash, Loader2, X } from 'lucide-react'
import React from 'react'

import { useIsMobile } from '@/shared/hooks/use-mobile'
import { useShortcut } from '@/shared/hooks/use-shortcut'
import { dispatchOpenPreviewTile } from '@/shared/lib/mosaic-events'
import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from '@/shared/ui/command'
import { Dialog, DialogContent } from '@/shared/ui/dialog'

import { fetchDocumentContent, listDocuments, type Document } from '@/entities/document'
import { listTags } from '@/entities/tag'

const trimLeadingOwner = (segments: string[]) => {
  if (segments.length <= 1) return segments
  const first = segments[0] ?? ''
  const looksLikeOwner = /^[0-9a-f-]{36}$/i.test(first) || first.toLowerCase().includes('@')
  return looksLikeOwner ? segments.slice(1) : segments
}

const getPathSegments = (path?: string | null) => {
  if (!path) return []
  const parts = path.split('/').filter((part) => part.length > 0)
  return trimLeadingOwner(parts)
}

const formatDisplayPath = (path?: string | null) => {
  const segments = getPathSegments(path)
  if (segments.length === 0) return null
  return segments.join(' / ')
}

const normalizePathValue = (path?: string | null) => {
  const segments = getPathSegments(path)
  if (segments.length === 0) return null
  return segments.join('/').toLowerCase()
}

type Props = { open: boolean; onOpenChange: (open: boolean) => void; presetTag?: string | null }

type TagHit = { name: string; count: number }
type DocumentHit = Pick<Document, 'id' | 'title' | 'path' | 'type'>

export default function SearchDialog({ open, onOpenChange, presetTag }: Props) {
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const [query, setQuery] = React.useState('')
  const [docs, setDocs] = React.useState<DocumentHit[]>([])
  const [tags, setTags] = React.useState<TagHit[]>([])
  const [selectedTag, setSelectedTag] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)
  const [activeItem, setActiveItem] = React.useState<string | null>(null)
  const [previewContent, setPreviewContent] = React.useState('')
  const [previewError, setPreviewError] = React.useState<string | null>(null)
  const [previewLoading, setPreviewLoading] = React.useState(false)

  const normalizedQuery = query.trim()
  const isTagShortcut = normalizedQuery.startsWith('#')
  const tagFilter = normalizedQuery.replace(/^#/, '').toLowerCase()
  const hasPathShortcut = !isTagShortcut && normalizedQuery.includes('/')
  const lastSlashIndex = hasPathShortcut ? normalizedQuery.lastIndexOf('/') : -1
  const folderFilterRaw = hasPathShortcut ? normalizedQuery.slice(0, lastSlashIndex).trim().replace(/^\/+|\/+$/g, '') : ''
  const folderFilter = folderFilterRaw ? folderFilterRaw.toLowerCase() : null
  const docQueryInput = hasPathShortcut ? normalizedQuery.slice(lastSlashIndex + 1) : normalizedQuery
  const docQuery = isTagShortcut ? '' : docQueryInput.trim()
  const serverQuery = !hasPathShortcut && !isTagShortcut ? (docQuery || null) : null

  const lastDocValueRef = React.useRef<string | null>(null)
  const previewCache = React.useRef<Map<string, string>>(new Map())

  const handleNavigate = React.useCallback(
    (id: string) => {
      onOpenChange(false)
      navigate({ to: '/document/$id', params: { id } })
    },
    [navigate, onOpenChange],
  )

  const activeDocId = activeItem && activeItem.startsWith('doc-') ? activeItem.replace('doc-', '') : null

  useShortcut(
    'file-tree.open.tile',
    React.useCallback(
      (event) => {
        if (!open) return
        if (!activeDocId) return
        dispatchOpenPreviewTile(activeDocId)
        onOpenChange(false)
        event.preventDefault()
        event.stopPropagation()
      },
      [activeDocId, onOpenChange, open],
    ),
    { preventDefault: false },
  )

  React.useEffect(() => {
    if (!open) {
      setQuery('')
      setSelectedTag(null)
      setDocs([])
      setTags([])
      setActiveItem(null)
      setPreviewContent('')
      setPreviewError(null)
      setPreviewLoading(false)
      lastDocValueRef.current = null
      previewCache.current.clear()
      return
    }

    let cancelled = false
    ;(async () => {
      try {
        const res = (await listTags(undefined)) as TagHit[]
        if (!cancelled) setTags(res ?? [])
      } catch {
        if (!cancelled) setTags([])
      }
    })()
    return () => {
      cancelled = true
    }
  }, [open])

  React.useEffect(() => {
    if (open) {
      setSelectedTag(presetTag ?? null)
    }
  }, [open, presetTag])

  React.useEffect(() => {
    if (!open) return
    let active = true
    const handle = setTimeout(async () => {
      setLoading(true)
      try {
        const res = await listDocuments({
          query: serverQuery,
          tag: selectedTag ?? null,
        })
        const items = (res?.items ?? []) as DocumentHit[]
        const onlyDocuments = items.filter((item) => item.type === 'document')
        if (active) setDocs(onlyDocuments)
      } catch {
        if (active) setDocs([])
      } finally {
        if (active) setLoading(false)
      }
    }, 160)
    return () => {
      active = false
      clearTimeout(handle)
    }
  }, [open, selectedTag, serverQuery])

  const folderIndex = React.useMemo(() => {
    const index = new Map<string, Array<{ normalized: string; value: string }>>()
    docs.forEach((doc) => {
      const segments = [...getPathSegments(doc.path)]
      if (segments.length === 0) return
      const titleNormalized = (doc.title ?? '').trim().toLowerCase()
      if (segments.length > 0 && titleNormalized && segments[segments.length - 1]?.toLowerCase() === titleNormalized) {
        segments.pop()
      }
      if (segments.length === 0) return
      let parentNormalized = ''
      segments.forEach((segment) => {
        const normalizedSegment = segment.toLowerCase()
        const list = index.get(parentNormalized) ?? []
        if (!list.some((item) => item.normalized === normalizedSegment)) {
          list.push({ normalized: normalizedSegment, value: segment })
          list.sort((a, b) => a.value.localeCompare(b.value))
        }
        index.set(parentNormalized, list)
        parentNormalized = parentNormalized ? `${parentNormalized}/${normalizedSegment}` : normalizedSegment
      })
    })
    return index
  }, [docs])

  const { visibleDocs, resolvedFolderLabel } = React.useMemo(() => {
    const filterByPath = (list: DocumentHit[], normalized: string) =>
      list.filter((doc) => {
        const filterable = normalizePathValue(doc.path)
        if (!filterable) return false
        return filterable.startsWith(normalized)
      })

    if (!folderFilter) {
      if (!docQuery) return { visibleDocs: docs, resolvedFolderLabel: null }
      const lowered = docQuery.toLowerCase()
      return {
        visibleDocs: docs.filter((doc) => doc.title.toLowerCase().includes(lowered)),
        resolvedFolderLabel: null,
      }
    }

    let normalized = folderFilter
    let matches = filterByPath(docs, normalized)
    let label = folderFilterRaw || null

    if (docQuery) {
      const lowered = docQuery.toLowerCase()
      const deeperRaw = folderFilterRaw ? `${folderFilterRaw}/${docQuery}` : docQuery
      const deeperNormalized = deeperRaw.toLowerCase()

      const hasDeeperMatches = matches.some((doc) => {
        const filterable = normalizePathValue(doc.path)
        if (!filterable) return false
        return (
          filterable === deeperNormalized ||
          filterable.startsWith(`${deeperNormalized}/`)
        )
      })

      if (hasDeeperMatches) {
        normalized = deeperNormalized
        matches = filterByPath(docs, normalized)
        label = deeperRaw
      } else {
        matches = matches.filter((doc) => doc.title.toLowerCase().includes(lowered))
      }
    }

    return { visibleDocs: matches, resolvedFolderLabel: label }
  }, [docs, folderFilter, folderFilterRaw, docQuery])

  const handleInputKeyDown = React.useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key !== 'Tab') return
      const target = event.currentTarget
      if (target.selectionStart !== target.selectionEnd || target.selectionStart !== target.value.length) return
      const currentValue = target.value
      if (currentValue.trim().startsWith('#')) return

      const slashIndex = currentValue.lastIndexOf('/')
      const baseDisplay = slashIndex >= 0 ? currentValue.slice(0, slashIndex) : ''
      const partial = slashIndex >= 0 ? currentValue.slice(slashIndex + 1) : currentValue

      const cleanedBase = baseDisplay.replace(/^\/+|\/+$/g, '')
      const baseNormalized = cleanedBase.toLowerCase()
      const candidates = folderIndex.get(baseNormalized) ?? []
      if (candidates.length === 0) return

      const loweredPartial = partial.toLowerCase()
      let match =
        loweredPartial.length === 0
          ? candidates[0]
          : candidates.find((candidate) => candidate.normalized.startsWith(loweredPartial))

      if (!match) return

      event.preventDefault()
      const prefix = slashIndex >= 0 ? `${currentValue.slice(0, slashIndex + 1)}` : ''
      const nextValue = `${prefix}${match.value}/`
      setQuery(nextValue)
    },
    [folderIndex],
  )

  React.useEffect(() => {
    if (!open) return
    if (visibleDocs.length === 0) {
      lastDocValueRef.current = null
      if (activeItem?.startsWith('doc-')) {
        setActiveItem(null)
      }
      return
    }

    const currentVisible =
      activeItem?.startsWith('doc-') && visibleDocs.some((doc) => `doc-${doc.id}` === activeItem)
    if (currentVisible) return

    const fallbackDocValue =
      (lastDocValueRef.current &&
        visibleDocs.some((doc) => `doc-${doc.id}` === lastDocValueRef.current) &&
        lastDocValueRef.current) ||
      `doc-${visibleDocs[0]!.id}`

    lastDocValueRef.current = fallbackDocValue
    if (!activeItem || activeItem.startsWith('doc-')) {
      setActiveItem(fallbackDocValue)
    }
  }, [visibleDocs, activeItem, open])

  const handleCommandValueChange = React.useCallback((value: string) => {
    setActiveItem(value || null)
    if (value && value.startsWith('doc-')) {
      lastDocValueRef.current = value
    }
  }, [])

  const forceFocusDocList = React.useCallback(() => {
    const fallback =
      (lastDocValueRef.current && visibleDocs.some((doc) => `doc-${doc.id}` === lastDocValueRef.current)
        ? lastDocValueRef.current
        : visibleDocs.length > 0
          ? `doc-${visibleDocs[0]!.id}`
          : null)
    if (fallback) {
      lastDocValueRef.current = fallback
      setActiveItem(fallback)
    }
  }, [visibleDocs])

  const handleTagToggle = React.useCallback(
    (tagName: string | null) => {
      setSelectedTag((prev) => {
        if (tagName === null) return null
        return prev === tagName ? null : tagName
      })
      setQuery('')
      forceFocusDocList()
    },
    [forceFocusDocList],
  )

  const selectedDoc = activeDocId ? visibleDocs.find((doc) => doc.id === activeDocId) : undefined

  React.useEffect(() => {
    if (!open) return
    if (!activeDocId) {
      setPreviewContent('')
      setPreviewError(null)
      setPreviewLoading(false)
      return
    }

    const cached = previewCache.current.get(activeDocId)
    if (cached !== undefined) {
      setPreviewContent(cached)
      setPreviewError(null)
      setPreviewLoading(false)
      return
    }

    let cancelled = false
    setPreviewLoading(true)
    setPreviewError(null)

    ;(async () => {
      try {
        const res = await fetchDocumentContent(activeDocId)
        if (cancelled) return
        const content =
          typeof res === 'object' && res !== null && 'content' in (res as any)
            ? ((res as any).content as string) ?? ''
            : ''
        previewCache.current.set(activeDocId, content)
        setPreviewContent(content)
        setPreviewError(null)
      } catch {
        if (!cancelled) {
          setPreviewContent('')
          setPreviewError('Failed to load preview')
        }
      } finally {
        if (!cancelled) setPreviewLoading(false)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [activeDocId, open])

  const filteredTags = React.useMemo(() => {
    if (!tags || tags.length === 0) return []
    if (!tagFilter) return tags.slice(0, 20)
    return tags.filter((tag) => tag.name.toLowerCase().includes(tagFilter)).slice(0, 20)
  }, [tags, tagFilter])

  const tagHeading = selectedTag ? `Tags • #${selectedTag}` : 'Tags'
  const folderHeadingLabel = resolvedFolderLabel ?? folderFilterRaw
  const documentHeading = selectedTag
    ? `Documents • #${selectedTag}`
    : folderHeadingLabel
      ? `Documents • ${folderHeadingLabel}`
      : 'Documents'
  const truncatedPreview = previewContent.length > 8000 ? `${previewContent.slice(0, 8000)}\n...` : previewContent

  const previewBody = (() => {
    if (!activeDocId) {
      return (
        <p className="text-sm text-muted-foreground">Select a document on the left to inspect its Markdown.</p>
      )
    }
    if (previewLoading) {
      return (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Loading preview...</span>
        </div>
      )
    }
    if (previewError) {
      return <p className="text-sm text-destructive">{previewError}</p>
    }
    if (!truncatedPreview) {
      return <p className="text-sm text-muted-foreground">This document has no content yet.</p>
    }
    return (
      <pre className="max-h-full whitespace-pre-wrap break-words font-mono text-sm leading-relaxed text-foreground/90">
        {truncatedPreview}
      </pre>
    )
  })()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        showCloseButton={false}
        className={cn('sm:max-w-[85vw] max-w-[95vw] h-[90vh] p-0 flex flex-col', overlayPanelClass)}
      >
        <div className="flex flex-col gap-1 border-b border-border/40 bg-transparent px-6 py-4">
          <p className="text-sm font-semibold leading-tight text-foreground">Quick search</p>
          <p className="text-xs text-muted-foreground">
            Use ↑/↓ to move, Enter to open, Shift+Enter to open in a tile, #tag for tags, and folder/ to scope by path.
          </p>
        </div>
        <div className="flex h-full min-h-0 min-w-0 flex-col md:flex-row">
          <div className="flex min-h-0 flex-1 flex-col border-b border-border/40 bg-transparent md:w-[55%] md:border-b-0 md:border-r md:border-border/40">
            <Command
              value={activeItem ?? undefined}
              onValueChange={handleCommandValueChange}
              shouldFilter={false}
              loop
              className="flex h-full flex-col rounded-none border-none bg-transparent"
            >
              <CommandInput
                value={query}
                autoFocus
                placeholder="Search documents or #tag..."
                onValueChange={setQuery}
                onKeyDown={handleInputKeyDown}
                className="text-base"
              />
              <CommandList className="flex-1 min-h-0 space-y-4 overflow-y-auto px-3 py-4 max-h-none">
                <CommandGroup heading={tagHeading} className="space-y-1">
                  {selectedTag && (
                    <CommandItem value="clear-tag-filter" className="text-sm" onSelect={() => handleTagToggle(null)}>
                      <X className="h-4 w-4 text-muted-foreground" />
                      <span>Clear tag filter</span>
                    </CommandItem>
                  )}
                  {filteredTags.map((tag) => {
                    const isActive = tag.name === selectedTag
                    return (
                      <CommandItem
                        key={`tag-${tag.name}`}
                        value={`tag-${tag.name}`}
                        className={cn('text-sm', isActive && 'bg-primary/10 text-foreground')}
                        onSelect={() => handleTagToggle(tag.name)}
                      >
                        <Hash className="h-4 w-4 text-muted-foreground" />
                        <span className="flex-1 truncate font-medium text-foreground">#{tag.name}</span>
                        <CommandShortcut>{tag.count}</CommandShortcut>
                      </CommandItem>
                    )
                  })}
                  {filteredTags.length === 0 && (
                    <div className="px-2 py-1 text-xs text-muted-foreground/80">No tags match this filter.</div>
                  )}
                </CommandGroup>
                <CommandSeparator alwaysRender />
                <CommandGroup heading={documentHeading} className="space-y-1">
                  {loading && (
                    <CommandItem value="loading-docs" disabled>
                      <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                      <span>Searching...</span>
                    </CommandItem>
                  )}
                  {!loading && visibleDocs.length === 0 && (
                    <CommandItem value="no-docs" disabled className="text-xs text-muted-foreground">
                      No documents found.
                    </CommandItem>
                  )}
                  {!loading &&
                    visibleDocs.map((doc) => {
                      const value = `doc-${doc.id}`
                      const displayPath = formatDisplayPath(doc.path)
                      return (
                        <CommandItem key={value} value={value} className="text-sm" onSelect={() => handleNavigate(doc.id)}>
                          <FileText className="h-4 w-4 text-muted-foreground" />
                          <div className="flex min-w-0 flex-col gap-0.5">
                            <span className="truncate font-medium text-foreground">{doc.title || 'Untitled Document'}</span>
                            {displayPath && <span className="truncate text-xs text-muted-foreground">{displayPath}</span>}
                          </div>
                          <CommandShortcut>Enter</CommandShortcut>
                        </CommandItem>
                      )
                    })}
                </CommandGroup>
              </CommandList>
            </Command>
          </div>
          {!isMobile && (
            <div className="flex min-h-0 flex-1 flex-col bg-transparent p-4 md:w-[45%]">
              <div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
                <span>Preview</span>
                {selectedDoc && (
                  <span className="truncate text-[11px] text-muted-foreground/80">
                    {formatDisplayPath(selectedDoc.path) || selectedDoc.title || 'Untitled Document'}
                  </span>
                )}
              </div>
              <div className="flex-1 overflow-auto rounded-2xl border border-border/30 bg-background/30 backdrop-blur-sm p-4">
                {previewBody}
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
