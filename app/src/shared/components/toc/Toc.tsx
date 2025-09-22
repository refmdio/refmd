"use client"

import { ChevronRight, ChevronDown } from 'lucide-react'
import React, { memo, useCallback, useEffect, useRef, useState } from 'react'

import { useActiveHeading } from '@/shared/hooks/use-active-heading'
import { cn } from '@/shared/lib/utils'

type TocProps = {
  contentSelector?: string
  onItemClick?: (id: string) => void
  className?: string
  containerRef?: React.RefObject<HTMLElement>
  small?: boolean
  floating?: boolean
}

type HeadingNode = {
  id: string
  text: string
  level: number
  children: HeadingNode[]
}

function buildHeadingTree(headings: Array<{ id: string; text: string; level: number }>): HeadingNode[] {
  const root: HeadingNode = { id: '__root', text: '', level: 0, children: [] }
  const stack: HeadingNode[] = [root]
  headings.forEach((h) => {
    if (!h.id) return
    const node: HeadingNode = { ...h, children: [] }
    while (stack.length > 1 && h.level <= stack[stack.length - 1].level) {
      stack.pop()
    }
    stack[stack.length - 1].children.push(node)
    stack.push(node)
  })
  return root.children
}

function TocComponent({
  contentSelector = '.markdown-preview',
  onItemClick,
  className,
  containerRef,
  small,
  floating,
}: TocProps) {
  const activeId = useActiveHeading(containerRef)
  const [nodes, setNodes] = useState<HeadingNode[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const observerRef = useRef<MutationObserver | null>(null)
  const containerSelectorRef = useRef(contentSelector)
  const slugCountsRef = useRef<Map<string, number>>(new Map())

  const assignId = useCallback((el: Element, text: string) => {
    const doc = el.ownerDocument || document
    const base = text
      .toLowerCase()
      .trim()
      .replace(/[\s]+/g, '-')
      .replace(/[^a-z0-9\-]/g, '')
      .replace(/-{2,}/g, '-')
      .replace(/^-+|-+$/g, '') || 'section'
    const counts = slugCountsRef.current
    const usedCount = counts.get(base) ?? 0
    let slug = usedCount === 0 ? base : `${base}-${usedCount}`
    let counter = usedCount + 1
    while (doc.getElementById(slug)) {
      slug = `${base}-${counter++}`
    }
    counts.set(base, counter)
    ;(el as HTMLElement).id = slug
    return slug
  }, [])

  const scanHeadings = useCallback(() => {
    const container = document.querySelector(containerSelectorRef.current)
    if (!container) { setNodes([]); return }
    slugCountsRef.current.clear()
    const headings = Array.from(container.querySelectorAll('h1, h2, h3, h4, h5, h6'))
      .map((el) => {
        let id = (el as HTMLElement).id.trim()
        const text = (el.textContent || '').trim()
        const level = Number(el.tagName.replace('H', '')) || 1
        if (!text) return null
        if (!id) {
          id = assignId(el, text)
        }
        return { id, text, level }
      })
      .filter((h): h is { id: string; text: string; level: number } => !!h && !!h.id && !!h.text)
    const tree = buildHeadingTree(headings)
    setNodes(tree)
    setExpanded((prev) => {
      const next = new Set<string>()
      const restore = (items: HeadingNode[]) => {
        items.forEach((item) => {
          if (prev.has(item.id)) next.add(item.id)
          if (item.children.length) restore(item.children)
        })
      }
      restore(tree)
      return next
    })
  }, [])

  useEffect(() => {
    containerSelectorRef.current = contentSelector
    let raf = 0
    const setup = () => {
      const target = document.querySelector(contentSelector)
      if (!target) {
        raf = requestAnimationFrame(setup)
        return
      }
      observerRef.current?.disconnect()
      const observer = new MutationObserver(() => {
        requestAnimationFrame(scanHeadings)
      })
      observer.observe(target, { childList: true, subtree: true })
      observerRef.current = observer
      scanHeadings()
    }
    setup()
    return () => {
      if (raf) cancelAnimationFrame(raf)
      observerRef.current?.disconnect()
      observerRef.current = null
    }
  }, [contentSelector, scanHeadings])

  useEffect(() => {
    if (!activeId) return
    const path: string[] = []
    const traverse = (items: HeadingNode[], ancestors: string[]) => {
      for (const item of items) {
        const nextAncestors = [...ancestors, item.id]
        if (item.id === activeId) {
          path.push(...nextAncestors)
          return true
        }
        if (item.children.length && traverse(item.children, nextAncestors)) return true
      }
      return false
    }
    traverse(nodes, [])
    if (!path.length) return
    setExpanded(new Set(path))
  }, [activeId, nodes])

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const handleItemClick = useCallback((id: string) => {
    onItemClick?.(id)
  }, [onItemClick])

  const isSmall = small || className?.includes('text-xs')

  const renderTree = useCallback((items: HeadingNode[]) => (
    <ul className="toc-list ml-0 pl-0 space-y-1">
      {items.map((item) => {
        const hasChildren = item.children.length > 0
        const isExpanded = expanded.has(item.id)
        const Icon = isExpanded ? ChevronDown : ChevronRight
        return (
          <li key={item.id} className="toc-list-item">
            <div className="flex items-center gap-1">
              {hasChildren ? (
                <button
                  type="button"
                  className="toc-expand-icon inline-flex items-center justify-center text-muted-foreground"
                  onClick={(e) => { e.preventDefault(); e.stopPropagation(); toggle(item.id) }}
                >
                  <Icon className="w-3 h-3" />
                </button>
              ) : (
                <span className="w-3 h-3" />
              )}
              <a
                href={`#${item.id}`}
                className={cn('toc-link flex-1', activeId === item.id && 'is-active-link')}
                onClick={() => handleItemClick(item.id)}
              >
                {item.text}
              </a>
            </div>
            {hasChildren && isExpanded && (
              <div className="ml-4 mt-1">
                {renderTree(item.children)}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  ), [expanded, activeId, handleItemClick, toggle])

  return (
    <nav className={cn('h-full', floating && 'overflow-y-auto', className)}>
      <div className={cn(floating ? '' : 'sticky top-20', isSmall ? 'p-2' : 'p-4')}>
        {!isSmall && !floating && <h3 className="text-sm font-semibold mb-3 text-muted-foreground">Table of Contents</h3>}
        <div className={cn(
          'toc-container',
          floating ? '' : 'max-h-[70vh] overflow-y-auto',
          isSmall && 'text-xs'
        )}>
          {nodes.length ? renderTree(nodes) : (
            <p className="text-xs text-muted-foreground">No headings</p>
          )}
        </div>
      </div>
    </nav>
  )
}

export const Toc = memo(TocComponent)
export default Toc
