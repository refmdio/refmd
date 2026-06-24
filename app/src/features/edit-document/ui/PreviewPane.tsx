"use client"

import { Menu, X } from 'lucide-react'
import React, { memo, useEffect, useMemo, useRef, useState } from 'react'

import { Toc } from '@/shared/components/toc/Toc'
import { useIsMobile } from '@/shared/hooks/use-mobile'
import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import type { ViewMode } from '@/shared/types/view-mode'
import { Button } from '@/shared/ui/button'

import Markdown from '@/features/edit-document/ui/Markdown'

import { useViewController } from '../public/useViewController'

export type PreviewCommentMarker = {
  threadId: string
  lineNumber: number
  resolved?: boolean
  active?: boolean
}

type PreviewCommentMarkerPosition = {
  lineNumber: number
  left: number
  top: number
  threads: PreviewCommentMarker[]
}

const EMPTY_COMMENT_MARKERS: PreviewCommentMarker[] = []
const COMMENT_MARKER_HIT_SIZE = 20
const COMMENT_MARKER_GAP = 8

type PreviewSourceAnchor = {
  line: number
  left: number
  top: number
  lineHeight: number
}

function sameCommentMarkerPositions(
  current: PreviewCommentMarkerPosition[],
  next: PreviewCommentMarkerPosition[],
) {
  if (current.length !== next.length) return false
  return current.every((item, index) => {
    const other = next[index]
    if (!other) return false
    if (
      item.lineNumber !== other.lineNumber ||
      item.left !== other.left ||
      item.top !== other.top
    ) {
      return false
    }
    if (item.threads.length !== other.threads.length) return false
    return item.threads.every((thread, threadIndex) => {
      const otherThread = other.threads[threadIndex]
      return (
        otherThread &&
        thread.threadId === otherThread.threadId &&
        Boolean(thread.resolved) === Boolean(otherThread.resolved) &&
        Boolean(thread.active) === Boolean(otherThread.active)
      )
    })
  })
}

export type PreviewPaneProps = {
  content: string
  viewMode?: ViewMode
  isSecondaryViewer?: boolean
  onScroll?: (scrollTop: number, scrollPercentage: number) => void
  onScrollAnchorLine?: (line: number) => void
  scrollPercentage?: number
  documentIdOverride?: string
  onNavigate?: (id: string) => void
  forceFloatingToc?: boolean
  stickToBottom?: boolean
  // Optional: scroll to a specific source line anchor (from editor)
  scrollToLine?: number
  onToggleTask?: (lineNumber: number, checked: boolean) => void
  taskToggleDisabled?: boolean
  commentMarkers?: PreviewCommentMarker[]
  activeCommentThreadId?: string | null
  onCommentMarkerSelect?: (threadId: string) => void
}

function PreviewPaneComponent({
  content,
  viewMode = 'preview',
  isSecondaryViewer = false,
  onScroll,
  onScrollAnchorLine,
  scrollPercentage,
  documentIdOverride,
  onNavigate,
  forceFloatingToc = false,
  stickToBottom = false,
  scrollToLine,
  onToggleTask,
  taskToggleDisabled,
  commentMarkers = EMPTY_COMMENT_MARKERS,
  activeCommentThreadId = null,
  onCommentMarkerSelect,
}: PreviewPaneProps) {
  const vc = useViewController()
  const onTagClickStable = React.useCallback((tag: string) => {
    vc.openSearch(tag)
  }, [vc])
  // Track user interaction to avoid overriding scroll position during active scrolling.
  useEffect(() => {
    const el = previewRef.current
    if (!el) return
    let wheelTimer: any = null
    const setUser = (v: boolean) => { ;(el as any).__userInteracting = v }
    const onPointerDown = () => setUser(true)
    const onPointerUp = () => setUser(false)
    const onLeave = () => setUser(false)
    const onWheel = () => { setUser(true); if (wheelTimer) clearTimeout(wheelTimer); wheelTimer = setTimeout(() => setUser(false), 150) }
    el.addEventListener('pointerdown', onPointerDown)
    el.addEventListener('pointerup', onPointerUp)
    el.addEventListener('pointercancel', onPointerUp)
    el.addEventListener('mouseleave', onLeave)
    el.addEventListener('wheel', onWheel, { passive: true })
    return () => {
      el.removeEventListener('pointerdown', onPointerDown)
      el.removeEventListener('pointerup', onPointerUp)
      el.removeEventListener('pointercancel', onPointerUp)
      el.removeEventListener('mouseleave', onLeave)
      el.removeEventListener('wheel', onWheel as any)
      if (wheelTimer) clearTimeout(wheelTimer)
      setUser(false)
    }
  }, [])
  const isMobile = useIsMobile()
  const [showFloatingToc, setShowFloatingToc] = useState(false)
  const floatingTocRef = useRef<HTMLDivElement | null>(null)
  const previewRef = useRef<HTMLDivElement | null>(null)
  const scrollRafId = useRef<number | null>(null)
  const anchorsRef = useRef<PreviewSourceAnchor[]>([])
  const [commentMarkerPositions, setCommentMarkerPositions] = useState<
    PreviewCommentMarkerPosition[]
  >([])
  const suppressSyncEmitRef = useRef(false)
  const suppressSyncEmitTimerRef = useRef<number | null>(null)
  const latestScrollStateRef = useRef({ scrollToLine, scrollPercentage, stickToBottom })

  useEffect(() => {
    latestScrollStateRef.current = { scrollToLine, scrollPercentage, stickToBottom }
  }, [scrollPercentage, scrollToLine, stickToBottom])

  const suppressSyncEmit = React.useCallback((ms = 140) => {
    if (typeof window === 'undefined') return
    suppressSyncEmitRef.current = true
    if (suppressSyncEmitTimerRef.current != null) {
      window.clearTimeout(suppressSyncEmitTimerRef.current)
    }
    suppressSyncEmitTimerRef.current = window.setTimeout(() => {
      suppressSyncEmitTimerRef.current = null
      suppressSyncEmitRef.current = false
    }, ms)
  }, [])

  // Build anchors from data-sourcepos (requires ReactMarkdown sourcePos)
  const rebuildAnchors = React.useCallback(() => {
    const container = previewRef.current
    if (!container) { anchorsRef.current = []; return }
    const rootRect = container.getBoundingClientRect()
    const nodes = Array.from(container.querySelectorAll('[data-sourcepos]')) as HTMLElement[]
    const blocks: PreviewSourceAnchor[] = []
    for (const el of nodes) {
      const sp = el.getAttribute('data-sourcepos') || ''
      const m = /^(\d+):\d+/.exec(sp)
      if (!m) continue
      const line = parseInt(m[1], 10)
      if (!Number.isFinite(line)) continue
      if (el.offsetParent === null || el.offsetHeight <= 0) continue
      const r = el.getBoundingClientRect()
      const style = window.getComputedStyle(el)
      const parsedLineHeight = parseFloat(style.lineHeight)
      const lineHeight = Number.isFinite(parsedLineHeight)
        ? parsedLineHeight
        : Math.min(Math.max(r.height, 18), 32)
      const left = (r.left - rootRect.left) + container.scrollLeft
      const top = (r.top - rootRect.top) + container.scrollTop
      blocks.push({ line, left, top, lineHeight })
    }
    blocks.sort((a, b) => a.line - b.line || a.top - b.top || a.left - b.left)
    const dedup: PreviewSourceAnchor[] = []
    let lastLine = -1
    for (const b of blocks) {
      if (b.line !== lastLine) { dedup.push(b); lastLine = b.line }
    }
    anchorsRef.current = dedup
  }, [])

  const rebuildCommentMarkerPositions = React.useCallback(() => {
    const container = previewRef.current
    const markers = commentMarkers
      .filter((marker) => Number.isFinite(marker.lineNumber))
      .map((marker) => ({
        ...marker,
        lineNumber: Math.max(1, Math.floor(marker.lineNumber)),
      }))
      .sort((a, b) => a.lineNumber - b.lineNumber)

    if (!container || markers.length === 0) {
      setCommentMarkerPositions((current) =>
        current.length ? [] : current,
      )
      return
    }

    if (!anchorsRef.current.length) {
      rebuildAnchors()
    }

    const anchors = anchorsRef.current
    if (!anchors.length) {
      setCommentMarkerPositions((current) =>
        current.length ? [] : current,
      )
      return
    }

    const grouped = new Map<number, PreviewCommentMarker[]>()
    for (const marker of markers) {
      const current = grouped.get(marker.lineNumber) ?? []
      current.push(marker)
      grouped.set(marker.lineNumber, current)
    }

    const next = Array.from(grouped.entries())
      .map(([lineNumber, threads]) => {
        let lo = 0
        let hi = anchors.length - 1
        let best = 0
        while (lo <= hi) {
          const mid = (lo + hi) >> 1
          if (anchors[mid].line <= lineNumber) {
            best = mid
            lo = mid + 1
          } else {
            hi = mid - 1
          }
        }
        const markerTop =
          anchors[best].top + (anchors[best].lineHeight / 2) - (COMMENT_MARKER_HIT_SIZE / 2)
        const markerLeft =
          anchors[best].left - COMMENT_MARKER_HIT_SIZE - COMMENT_MARKER_GAP
        return {
          lineNumber,
          left: Math.max(4, Math.round(markerLeft)),
          top: Math.max(4, Math.round(markerTop)),
          threads,
        }
      })
      .sort((a, b) => a.top - b.top || a.lineNumber - b.lineNumber)

    setCommentMarkerPositions((current) =>
      sameCommentMarkerPositions(current, next) ? current : next,
    )
  }, [commentMarkers, rebuildAnchors])

  const scrollToPercentage = React.useCallback((percentage?: number) => {
    const container = previewRef.current
    if (percentage == null || !container) return false
    if ((container as any).__userInteracting === true) return false

    const { scrollHeight, clientHeight } = container
    const denom = Math.max(1, scrollHeight - clientHeight)
    suppressSyncEmit()
    container.scrollTop = Math.round(denom * Math.min(1, Math.max(0, percentage)))
    return true
  }, [suppressSyncEmit])

  const scrollToNearestAnchor = React.useCallback((line?: number, fallbackPercentage?: number) => {
    const container = previewRef.current
    if (line == null || !container) return false
    if ((container as any).__userInteracting === true) return false

    if (!anchorsRef.current.length) {
      rebuildAnchors()
    }

    const anchors = anchorsRef.current
    if (!anchors.length) {
      return scrollToPercentage(fallbackPercentage)
    }

    // Find greatest anchor.line <= target line
    let lo = 0, hi = anchors.length - 1, best = 0
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      if (anchors[mid].line <= line) { best = mid; lo = mid + 1 } else { hi = mid - 1 }
    }
    const targetTop = anchors[best].top
    const margin = 12
    const maxTop = Math.max(0, container.scrollHeight - container.clientHeight)
    const nextTop = Math.max(0, Math.min(maxTop, targetTop - margin))
    requestAnimationFrame(() => {
      suppressSyncEmit()
      container.scrollTop = nextTop
    })
    return true
  }, [rebuildAnchors, scrollToPercentage, suppressSyncEmit])

  const markdownWrapperCls = useMemo(() =>
    cn(
      'prose prose-neutral dark:prose-invert break-words overflow-wrap-anywhere',
      viewMode === 'preview' ? 'max-w-6xl mx-auto' : 'max-w-none',
      isSecondaryViewer && 'markdown-preview-secondary',
    ), [viewMode, isSecondaryViewer])

  const showAsideToc = viewMode === 'preview' && !isMobile && !isSecondaryViewer && !forceFloatingToc
  const showFloatingTrigger = viewMode === 'split' || (viewMode === 'preview' && isMobile) || isSecondaryViewer || forceFloatingToc

  // Apply external scroll percentage to container (fallback when no anchor line)
  useEffect(() => {
    // If anchor-line based scroll is provided, it takes precedence
    if (scrollToLine != null) return
    scrollToPercentage(scrollPercentage)
  }, [scrollPercentage, scrollToLine, scrollToPercentage])

  // If editor is at bottom (pct≈1) and content grows, keep preview pinned to bottom
  useEffect(() => {
    if (scrollToLine != null) return
    if (!stickToBottom && !(scrollPercentage != null && scrollPercentage >= 0.999)) return
    const el = previewRef.current
    if (!el) return
    if ((el as any).__userInteracting === true) return
    const pin = () => {
      const { scrollHeight, clientHeight } = el
      const denom = Math.max(0, scrollHeight - clientHeight)
      suppressSyncEmit()
      el.scrollTop = denom
    }
    // Wait for layout after content change
    requestAnimationFrame(() => { requestAnimationFrame(pin) })
  }, [content, scrollPercentage, stickToBottom, scrollToLine, suppressSyncEmit])

  // Rebuild anchors after content or container size changes
  useEffect(() => {
    const el = previewRef.current
    if (!el) return
    const build = () => {
      rebuildAnchors()
      rebuildCommentMarkerPositions()
    }
    // build after layout settles
    requestAnimationFrame(() => { requestAnimationFrame(build) })
    let ro: ResizeObserver | null = null
    if ('ResizeObserver' in window) {
      ro = new ResizeObserver(() => build())
      ro.observe(el)
    }
    return () => { try { ro?.disconnect() } catch {} }
  }, [content, rebuildAnchors, rebuildCommentMarkerPositions])

  useEffect(() => {
    requestAnimationFrame(() => {
      requestAnimationFrame(rebuildCommentMarkerPositions)
    })
  }, [rebuildCommentMarkerPositions])

  // Markdown HTML is rendered asynchronously, so source anchors can appear after
  // the raw content prop has already changed.
  useEffect(() => {
    const el = previewRef.current
    if (!el || typeof MutationObserver === 'undefined') return

    let frame: number | null = null
    const schedule = () => {
      if (frame != null) return
      frame = requestAnimationFrame(() => {
        frame = null
        rebuildAnchors()
        rebuildCommentMarkerPositions()
        const latest = latestScrollStateRef.current
        if (latest.scrollToLine != null) {
          scrollToNearestAnchor(latest.scrollToLine, latest.scrollPercentage)
        } else if (latest.stickToBottom || (latest.scrollPercentage != null && latest.scrollPercentage >= 0.999)) {
          const target = previewRef.current
          if (!target || (target as any).__userInteracting === true) return
          const { scrollHeight, clientHeight } = target
          suppressSyncEmit()
          target.scrollTop = Math.max(0, scrollHeight - clientHeight)
        }
      })
    }

    const observer = new MutationObserver(schedule)
    observer.observe(el, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: ['data-sourcepos'],
    })
    schedule()

    return () => {
      observer.disconnect()
      if (frame != null) cancelAnimationFrame(frame)
    }
  }, [rebuildAnchors, rebuildCommentMarkerPositions, scrollToNearestAnchor, suppressSyncEmit])

  // Scroll to nearest anchor for requested source line
  useEffect(() => {
    if (scrollToLine == null) return
    scrollToNearestAnchor(scrollToLine, scrollPercentage)
  }, [scrollPercentage, scrollToLine, scrollToNearestAnchor])

  // Cleanup rAF
  useEffect(() => () => {
    if (scrollRafId.current != null) cancelAnimationFrame(scrollRafId.current)
    if (suppressSyncEmitTimerRef.current != null) {
      window.clearTimeout(suppressSyncEmitTimerRef.current)
      suppressSyncEmitTimerRef.current = null
    }
  }, [])

  const handleFloatingItemClick = React.useCallback(() => setShowFloatingToc(false), [])
  const handleCommentMarkerClick = React.useCallback(
    (position: PreviewCommentMarkerPosition) => {
      if (!onCommentMarkerSelect || position.threads.length === 0) return
      const activeIndex = position.threads.findIndex(
        (thread) => thread.threadId === activeCommentThreadId,
      )
      const nextIndex =
        activeIndex >= 0 ? (activeIndex + 1) % position.threads.length : 0
      onCommentMarkerSelect(position.threads[nextIndex].threadId)
    },
    [activeCommentThreadId, onCommentMarkerSelect],
  )

  return (
    <div className="relative flex h-full w-full flex-1 min-h-0 flex-col bg-background overflow-hidden">
      <div
        className="refmd-preview-scroll-root relative flex-1 overflow-auto"
        ref={previewRef}
        onScroll={(e) => {
          // Throttle with rAF to reduce callbacks
          if (scrollRafId.current != null) cancelAnimationFrame(scrollRafId.current)
          const el = e.currentTarget as HTMLDivElement | null
          scrollRafId.current = requestAnimationFrame(() => {
            const target = el || previewRef.current
            if (!target) { scrollRafId.current = null; return }
            const { scrollTop, scrollHeight, clientHeight } = target
            const denom = Math.max(1, scrollHeight - clientHeight)
            const pct = Math.min(1, Math.max(0, scrollTop / denom))
            const anchors = anchorsRef.current
            if (!suppressSyncEmitRef.current) {
              const nearBottom = (scrollHeight - clientHeight - scrollTop) <= 4
              if (nearBottom && onScroll) {
                // At bottom: force editor to bottom using percentage sync to avoid partial reveal
                onScroll(scrollTop, 1)
              } else if (onScrollAnchorLine && anchors.length > 0) {
                // Map current scrollTop to nearest anchor line (top of viewport)
                const topPos = scrollTop + 1
                let lo = 0, hi = anchors.length - 1, best = 0
                while (lo <= hi) {
                  const mid = (lo + hi) >> 1
                  if (anchors[mid].top <= topPos) { best = mid; lo = mid + 1 } else { hi = mid - 1 }
                }
                const line = anchors[Math.max(0, Math.min(best, anchors.length - 1))].line
                onScrollAnchorLine(line)
              } else if (onScroll) {
                // Fallback to percentage-based sync if no anchors
                onScroll(scrollTop, pct)
              }
            }
            scrollRafId.current = null
          })
        }}
      >
        {commentMarkerPositions.length ? (
          <div className="pointer-events-none absolute inset-0 z-30">
            {commentMarkerPositions.map((position) => {
              const active = position.threads.some(
                (thread) =>
                  thread.active || thread.threadId === activeCommentThreadId,
              )
              const unresolved = position.threads.some(
                (thread) => !thread.resolved,
              )
              return (
                <button
                  key={`${position.lineNumber}:${position.threads.map((thread) => thread.threadId).join(',')}`}
                  type="button"
                  aria-label={
                    position.threads.length > 1
                      ? `${position.threads.length} comments`
                      : 'Comment'
                  }
                  title={
                    position.threads.length > 1
                      ? `${position.threads.length} comments`
                      : 'Comment'
                  }
                  className={cn(
                    'pointer-events-auto absolute flex h-5 min-w-5 items-center justify-center rounded-full transition-colors',
                    active && 'bg-primary/10',
                    !active && unresolved && 'hover:bg-primary/10',
                    !active && !unresolved && 'hover:bg-muted/60',
                  )}
                  style={{ left: position.left, top: position.top }}
                  onMouseDown={(event) => event.stopPropagation()}
                  onClick={(event) => {
                    event.stopPropagation()
                    handleCommentMarkerClick(position)
                  }}
                >
                  <span
                    className={cn(
                      'flex items-center justify-center rounded-full border shadow-sm',
                      position.threads.length > 1
                        ? 'h-4 min-w-4 px-1 text-[9px] font-medium leading-none'
                        : 'h-2.5 w-2.5',
                      active &&
                        'border-primary bg-primary text-primary-foreground',
                      !active &&
                        unresolved &&
                        'border-primary/60 bg-background/95 text-primary',
                      !active &&
                        !unresolved &&
                        'border-border/70 bg-background/80 text-muted-foreground',
                    )}
                  >
                    {position.threads.length > 1 ? position.threads.length : null}
                  </span>
                </button>
              )
            })}
          </div>
        ) : null}
        <div
          className={cn(
            'w-full mx-auto flex gap-8 px-4 pb-4 pt-0 sm:px-6 sm:pb-6 sm:pt-0 md:px-8 md:pb-8',
            viewMode === 'preview' && 'max-w-6xl',
          )}
        >
          <div className="flex-1 min-w-0 overflow-hidden">
            <Markdown
              content={content}
              className={markdownWrapperCls}
              documentIdOverride={documentIdOverride}
              onNavigate={onNavigate}
              onTagClick={onTagClickStable}
              onToggleTask={onToggleTask}
              taskToggleDisabled={taskToggleDisabled}
            />
          </div>
          <aside className={cn('w-64 shrink-0', showAsideToc ? 'hidden lg:block' : 'hidden')}>
            <Toc
              contentSelector={isSecondaryViewer ? '.markdown-preview-secondary' : '.markdown-preview:not(.markdown-preview-secondary)'}
              containerRef={!isMobile ? (previewRef as React.RefObject<HTMLElement>) : undefined}
            />
          </aside>
        </div>
      </div>

      {showFloatingTrigger && (
        <Button
          onClick={() => setShowFloatingToc((s) => !s)}
          className={cn(
            'p-3 rounded-full border border-primary/60 bg-primary text-primary-foreground shadow-lg transition-all hover:bg-primary/90 hover:shadow-xl z-40',
            (isMobile || forceFloatingToc) ? 'fixed bottom-6 right-6' : 'absolute bottom-6 right-6'
          )}
          title="Table of Contents"
          size="icon"
        >
          <Menu className="h-5 w-5" />
        </Button>
      )}

      {showFloatingToc && (
        <div
          ref={floatingTocRef}
          className={cn(
            overlayPanelClass,
            (isMobile || forceFloatingToc)
              ? 'fixed bottom-24 right-6 w-[min(320px,calc(100%-2.5rem))] z-40'
              : 'absolute bottom-20 right-6 w-[300px] max-w-[calc(100%-3rem)] z-40',
          )}
        >
          <div className="flex items-center justify-between border-b border-border/50 px-3 py-2">
            <h3 className="text-xs font-semibold pr-4">Table of Contents</h3>
            <Button
              onClick={() => setShowFloatingToc(false)}
              className="p-1 h-auto w-auto rounded-md text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground flex-shrink-0"
              variant="ghost"
              size="sm"
            >
              <X className="h-3 w-3" />
            </Button>
          </div>
          <div className="max-h-[60vh] overflow-y-auto">
            <Toc
              contentSelector={isSecondaryViewer ? '.markdown-preview-secondary' : '.markdown-preview:not(.markdown-preview-secondary)'}
              containerRef={!isMobile ? (previewRef as React.RefObject<HTMLElement>) : undefined}
              onItemClick={handleFloatingItemClick}
              floating
              small
            />
          </div>
        </div>
      )}
    </div>
  )
}

export const PreviewPane = memo(PreviewPaneComponent)
export default PreviewPane
