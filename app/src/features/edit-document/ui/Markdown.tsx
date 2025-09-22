import morphdom from 'morphdom'
import { memo, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import { API_BASE_URL } from '@/shared/lib/config'
import { cn } from '@/shared/lib/utils'

import { upgradeAll } from '@/entities/document/wc/markdown/hydrate-all'
import { renderMarkdown } from '@/entities/markdown'

import { ImageModal } from '@/features/edit-document/ui/ImageModal'
import '@/entities/document/wc/wiki/wikilink'

// Prism for client-side highlighting to match previous theme
// Using server-side highlighting; no Prism import

type Props = {
  content: string
  isPublic?: boolean
  onTagClick?: (tag: string) => void
  onNavigate?: (id: string) => void
  className?: string
  documentIdOverride?: string
  onToggleTask?: (lineNumber: number, checked: boolean) => void
  taskToggleDisabled?: boolean
}

function ServerMarkdown({ content, className, documentIdOverride, onTagClick, onToggleTask, taskToggleDisabled }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [html, setHtml] = useState<string>('')
  const [modalImage, setModalImage] = useState<{ src: string; alt?: string } | null>(null)
  const previousHtmlRef = useRef<string>('')

const requestRef = useRef<any | null>(null)
const queuedRef = useRef<{ text: string; override?: string } | null>(null)
const latestKeyRef = useRef<string>('')

  useEffect(() => () => {
    if (requestRef.current && typeof requestRef.current?.cancel === 'function') {
      try { requestRef.current.cancel() } catch {}
    }
    queuedRef.current = null
  }, [])

  const runRender = useCallback(
    async (text: string, override?: string) => {
      const requestKey = `${override ?? ''}::${text}`
      latestKeyRef.current = requestKey

      const apiOrigin = (() => { try { return new URL((API_BASE_URL || '')).origin } catch { return '' } })()
      let token: string | undefined
      try { token = new URLSearchParams(window.location.search).get('token') || undefined } catch {}

      const promise = renderMarkdown({
        text,
        options: {
          flavor: 'doc',
          features: ['gfm', 'mermaid', 'highlight'],
          sanitize: true,
          absolute_attachments: true as any,
          base_origin: apiOrigin as any,
          doc_id: override as any,
          token: token as any,
        } as any,
      })

      requestRef.current = promise as any

      try {
        const out = await promise
        if (latestKeyRef.current === requestKey) {
          setHtml(out?.html || '')
        }
      } catch (error: any) {
        if (error?.name === 'AbortError' || error?.message === 'Cancelled') {
          return
        }
        if (latestKeyRef.current === requestKey) {
          setHtml('')
        }
      } finally {
        requestRef.current = null
        if (queuedRef.current) {
          const next = queuedRef.current
          queuedRef.current = null
          void runRender(next.text, next.override)
        }
      }
    },
    [],
  )

  useEffect(() => {
    const next = { text: content, override: documentIdOverride }
    if (requestRef.current) {
      queuedRef.current = next
      if (typeof requestRef.current?.cancel === 'function') {
        try { requestRef.current.cancel() } catch {}
      }
      return
    }
    queuedRef.current = null
    void runRender(next.text, next.override)
  }, [content, documentIdOverride, runRender])

  useLayoutEffect(() => {
    const el = containerRef.current
    if (!el) return

    if (!previousHtmlRef.current) {
      el.innerHTML = html
    } else if (previousHtmlRef.current !== html) {
      const wrapper = el.cloneNode(false) as HTMLElement
      wrapper.innerHTML = html
      morphdom(el, wrapper, {
        childrenOnly: true,
        onBeforeElUpdated: (fromEl) => {
          if (fromEl.tagName === 'REFMD-WIKILINK' || fromEl.tagName === 'REFMD-ATTACHMENT') {
            return false
          }
          return true
        },
      })
    }
    previousHtmlRef.current = html

    const detachFns: Array<() => void> = []

    try {
      const maybeFns = upgradeAll(el)
      if (Array.isArray(maybeFns)) detachFns.push(...maybeFns)
    } catch {}

    const enableTaskToggle = typeof onToggleTask === 'function' && !taskToggleDisabled
    if (enableTaskToggle) {
      const checkboxes = Array.from(el.querySelectorAll('input[type="checkbox"]')) as HTMLInputElement[]
      for (const checkbox of checkboxes) {
        if (checkbox.dataset.refmdTaskInteractive === 'true') continue
        const li = checkbox.closest('[data-sourcepos]') as HTMLElement | null
        if (!li) continue
        const sourcepos = li.getAttribute('data-sourcepos') || ''
        const match = /^\s*(\d+):/.exec(sourcepos)
        const lineNumber = match ? parseInt(match[1], 10) : NaN
        if (!Number.isFinite(lineNumber)) continue

        checkbox.disabled = false
        checkbox.removeAttribute('disabled')
        checkbox.tabIndex = 0
        checkbox.dataset.refmdTaskInteractive = 'true'

        checkbox.setAttribute('aria-checked', checkbox.checked ? 'true' : 'false')
        const changeHandler = (event: Event) => {
          event.stopPropagation?.()
          const target = event.currentTarget as HTMLInputElement
          const nextState = !!target.checked
          try { onToggleTask?.(lineNumber, nextState) } catch {}
          target.setAttribute('aria-checked', nextState ? 'true' : 'false')
          if (nextState) target.setAttribute('checked', '')
          else target.removeAttribute('checked')
        }
        checkbox.addEventListener('change', changeHandler)
        detachFns.push(() => {
          checkbox.removeEventListener('change', changeHandler)
          checkbox.disabled = true
          checkbox.setAttribute('disabled', '')
          delete checkbox.dataset.refmdTaskInteractive
        })
      }
    }
    const imgs = Array.from(el.querySelectorAll('img')) as HTMLImageElement[]
    detachFns.push(...imgs.map((img) => {
      const handler = (e: Event) => {
        e.preventDefault()
        e.stopPropagation()
        setModalImage({ src: img.getAttribute('src') || '', alt: img.getAttribute('alt') || undefined })
      }
      img.addEventListener('click', handler)
      return () => img.removeEventListener('click', handler)
    }))

    const onTagClickHandler = (event: MouseEvent) => {
      const targetNode = event.target as Node | null
      if (!targetNode) return
      const rootEl = targetNode instanceof Element ? targetNode : targetNode.parentElement
      const hashtag = rootEl?.closest('.hashtag') as HTMLElement | null
      if (!hashtag) return
      event.preventDefault()
      event.stopPropagation()
      const raw = hashtag.getAttribute('data-tag') || hashtag.textContent || ''
      const tag = raw.trim().replace(/^#/, '')
      if (!tag) return
      if (onTagClick) {
        onTagClick(tag)
      } else if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
        try { window.dispatchEvent(new CustomEvent('refmd:open-search', { detail: { tag } })) } catch {}
      }
    }
    el.addEventListener('click', onTagClickHandler)
    detachFns.push(() => el.removeEventListener('click', onTagClickHandler))

    return () => { detachFns.forEach((fn) => fn()) }
  }, [html, onTagClick])

  return (
    <>
      <div className={cn('markdown-preview', className)} ref={containerRef} />
      {modalImage && (
        <ImageModal src={modalImage.src} alt={modalImage.alt} isOpen={!!modalImage} onClose={() => setModalImage(null)} />
      )}
    </>
  )
}

export default memo(ServerMarkdown)
