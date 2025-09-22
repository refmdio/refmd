import { RefObject, useEffect, useState } from 'react'

type UseInViewOptions = {
  root?: Element | null
  rootMargin?: string
  threshold?: number | number[]
}

export function useInView(target: RefObject<Element | null | undefined>, options: UseInViewOptions = {}) {
  const { root = null, rootMargin = '0px', threshold = 0 } = options
  const [isIntersecting, setIsIntersecting] = useState(false)

  useEffect(() => {
    const node = target.current
    if (!node) return

    if (typeof window === 'undefined' || !('IntersectionObserver' in window)) {
      setIsIntersecting(true)
      return
    }

    let cancelled = false
    const observer = new IntersectionObserver(
      (entries) => {
        if (cancelled) return
        for (const entry of entries) {
          if (entry.target === node) {
            setIsIntersecting(entry.isIntersecting || entry.intersectionRatio > 0)
          }
        }
      },
      { root, rootMargin, threshold },
    )

    observer.observe(node)

    return () => {
      cancelled = true
      observer.disconnect()
    }
  }, [target, root, rootMargin, threshold])

  return isIntersecting
}

export default useInView
