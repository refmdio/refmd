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

type Props = {
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
}

function PreviewPaneComponent({ content, viewMode = 'preview', isSecondaryViewer = false, onScroll, onScrollAnchorLine, scrollPercentage, documentIdOverride, onNavigate, forceFloatingToc = false, stickToBottom = false, scrollToLine, onToggleTask, taskToggleDisabled }: Props) {
  const vc = useViewController()
  const onTagClickStable = React.useCallback((tag: string) => {
    vc.openSearch(tag)
  }, [vc])
  // Track when user is actively interacting with preview to enable preview->editor sync
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
  const anchorsRef = useRef<Array<{ line: number; top: number }>>([])

  // Build anchors from data-sourcepos (requires ReactMarkdown sourcePos)
  const rebuildAnchors = React.useCallback(() => {
    const container = previewRef.current
    if (!container) { anchorsRef.current = []; return }
    const rootRect = container.getBoundingClientRect()
    const nodes = Array.from(container.querySelectorAll('[data-sourcepos]')) as HTMLElement[]
    const blocks: Array<{ line: number; top: number }> = []
    for (const el of nodes) {
      const sp = el.getAttribute('data-sourcepos') || ''
      const m = /^(\d+):\d+/.exec(sp)
      if (!m) continue
      const line = parseInt(m[1], 10)
      if (!Number.isFinite(line)) continue
      if (el.offsetParent === null || el.offsetHeight <= 0) continue
      const r = el.getBoundingClientRect()
      const top = (r.top - rootRect.top) + container.scrollTop
      blocks.push({ line, top })
    }
    blocks.sort((a, b) => a.line - b.line || a.top - b.top)
    const dedup: Array<{ line: number; top: number }> = []
    let lastLine = -1
    for (const b of blocks) {
      if (b.line !== lastLine) { dedup.push(b); lastLine = b.line }
    }
    anchorsRef.current = dedup
  }, [])

  const markdownWrapperCls = useMemo(() =>
    cn(
      'prose prose-neutral dark:prose-invert break-words overflow-wrap-anywhere',
      viewMode === 'preview' ? 'max-w-6xl mx-auto' : 'max-w-none',
      isSecondaryViewer && 'markdown-preview-secondary'
    ), [viewMode, isSecondaryViewer])

  const showAsideToc = viewMode === 'preview' && !isMobile && !isSecondaryViewer && !forceFloatingToc
  const showFloatingTrigger = viewMode === 'split' || (viewMode === 'preview' && isMobile) || isSecondaryViewer || forceFloatingToc

  // Apply external scroll percentage to container (fallback when no anchor line)
  useEffect(() => {
    // If anchor-line based scroll is provided, it takes precedence
    if (scrollToLine != null) return
    if (scrollPercentage == null || !previewRef.current) return
    const el = previewRef.current
    // Don't override while user is actively scrolling preview
    if ((el as any).__userInteracting === true) return
    const { scrollHeight, clientHeight } = el
    const denom = Math.max(1, scrollHeight - clientHeight)
    el.scrollTop = Math.round(denom * Math.min(1, Math.max(0, scrollPercentage)))
  }, [scrollPercentage, scrollToLine])

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
      el.scrollTop = denom
    }
    // Wait for layout after content change
    requestAnimationFrame(() => { requestAnimationFrame(pin) })
  }, [content, scrollPercentage, stickToBottom, scrollToLine])

  // Rebuild anchors after content or container size changes
  useEffect(() => {
    const el = previewRef.current
    if (!el) return
    const build = () => { rebuildAnchors() }
    // build after layout settles
    requestAnimationFrame(() => { requestAnimationFrame(build) })
    let ro: ResizeObserver | null = null
    if ('ResizeObserver' in window) {
      ro = new ResizeObserver(() => build())
      ro.observe(el)
    }
    return () => { try { ro?.disconnect() } catch {} }
  }, [content, rebuildAnchors])

  // Scroll to nearest anchor for requested source line
  useEffect(() => {
    if (scrollToLine == null) return
    const container = previewRef.current
    if (!container) return
    if ((container as any).__userInteracting === true) return
    const anchors = anchorsRef.current
    if (!anchors.length) return
    // Find greatest anchor.line <= target line
    let lo = 0, hi = anchors.length - 1, best = 0
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      if (anchors[mid].line <= scrollToLine) { best = mid; lo = mid + 1 } else { hi = mid - 1 }
    }
    const targetTop = anchors[best].top
    const margin = 12
    const maxTop = Math.max(0, container.scrollHeight - container.clientHeight)
    const nextTop = Math.max(0, Math.min(maxTop, targetTop - margin))
    requestAnimationFrame(() => {
      container.scrollTop = nextTop
    })
  }, [scrollToLine])

  // Cleanup rAF
  useEffect(() => () => { if (scrollRafId.current != null) cancelAnimationFrame(scrollRafId.current) }, [])

  const handleFloatingItemClick = React.useCallback(() => setShowFloatingToc(false), [])

  return (
    <div className="relative flex flex-1 min-h-0 flex-col bg-background overflow-hidden">
      <div
        className="flex-1 overflow-auto"
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
            // Only propagate when user is interacting with preview (wheel/drag)
            const isUser = (target as any).__userInteracting === true
            const nearBottom = (scrollHeight - clientHeight - scrollTop) <= 4
            if (isUser) {
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
