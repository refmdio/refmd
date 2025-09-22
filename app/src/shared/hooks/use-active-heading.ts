import { useEffect, useRef, useState } from 'react'

export function useActiveHeading(containerRef?: React.RefObject<HTMLElement>) {
  const [activeId, setActiveId] = useState('')
  const headingsRef = useRef<Map<string, Element>>(new Map())
  const mutationObserverRef = useRef<MutationObserver | null>(null)
  const scanTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const lastActiveIdRef = useRef('')

  useEffect(() => {
    const timer = setTimeout(() => {
      const updateActiveHeading = () => {
        const container = containerRef?.current
        const isWindowScroll = !container

        let containerTop = 0
        let containerHeight = window.innerHeight
        if (container) {
          const rect = container.getBoundingClientRect()
          containerTop = rect.top
          containerHeight = rect.height
        }

        let nextActive = ''
        let minDistance = Infinity
        headingsRef.current.forEach((heading, id) => {
          const rect = heading.getBoundingClientRect()
          const headingTop = rect.top - containerTop
          const threshold = isWindowScroll ? 100 : containerHeight * 0.3
          if (headingTop >= -100 && headingTop <= threshold) {
            const distance = Math.abs(headingTop)
            if (distance < minDistance) {
              minDistance = distance
              nextActive = id
            }
          }
        })
        if (!nextActive) {
          let lastBeforeTop = ''
          headingsRef.current.forEach((heading, id) => {
            const rect = heading.getBoundingClientRect()
            const headingTop = rect.top - containerTop
            if (headingTop <= 100) lastBeforeTop = id
          })
          nextActive = lastBeforeTop
        }
        if (nextActive && nextActive !== lastActiveIdRef.current) {
          lastActiveIdRef.current = nextActive
          setActiveId(nextActive)
        }
      }

      const scanHeadings = () => {
        if (scanTimeoutRef.current) clearTimeout(scanTimeoutRef.current)
        scanTimeoutRef.current = setTimeout(() => {
          const container = containerRef?.current || document
          const headings = container.querySelectorAll('h1[id], h2[id], h3[id], h4[id], h5[id], h6[id]')
          const newIds = Array.from(headings).map((h) => h.id).filter(Boolean)
          const oldIds = Array.from(headingsRef.current.keys())
          if (newIds.length !== oldIds.length || !newIds.every((id, i) => id === oldIds[i])) {
            headingsRef.current.clear()
            headings.forEach((h) => { if (h.id) headingsRef.current.set(h.id, h) })
            updateActiveHeading()
          }
        }, 50)
      }

      scanHeadings()

      let cleanupScroll: (() => void) | undefined
      const bindScrollTargets = () => {
        cleanupScroll?.()
        const primaryTarget = containerRef?.current
        const scrollTargets: Array<EventTarget> = []
        if (primaryTarget) scrollTargets.push(primaryTarget)
        scrollTargets.push(window)

        if (!scrollTargets.length) return

        let scrollTimeout: ReturnType<typeof setTimeout> | undefined
        const onScroll = () => {
          if (scrollTimeout) clearTimeout(scrollTimeout)
          scrollTimeout = setTimeout(updateActiveHeading, 16)
        }
        scrollTargets.forEach((target) => target.addEventListener('scroll', onScroll, { passive: true } as any))
        cleanupScroll = () => {
          scrollTargets.forEach((target) => (target as any).removeEventListener?.('scroll', onScroll))
        }
      }

      const ensureScrollTarget = () => {
        if (containerRef?.current) {
          bindScrollTargets()
        } else {
          requestAnimationFrame(ensureScrollTarget)
        }
      }

      bindScrollTargets()
      ensureScrollTarget()

      const observeTarget = containerRef?.current || document.body
      let mutationTimeout: ReturnType<typeof setTimeout> | undefined
      mutationObserverRef.current = new MutationObserver(() => {
        if (mutationTimeout) clearTimeout(mutationTimeout)
        mutationTimeout = setTimeout(() => {
          scanHeadings()
          bindScrollTargets()
        }, 100)
      })
      mutationObserverRef.current.observe(observeTarget, { childList: true, subtree: true, attributes: true, attributeFilter: ['id'] })

      return () => {
        cleanupScroll?.()
        mutationObserverRef.current?.disconnect()
      }
    }, 100)

    return () => {
      clearTimeout(timer)
      if (scanTimeoutRef.current) clearTimeout(scanTimeoutRef.current)
      mutationObserverRef.current?.disconnect()
    }
  }, [containerRef])

  return activeId
}
