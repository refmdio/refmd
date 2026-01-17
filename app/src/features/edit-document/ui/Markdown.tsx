import morphdom from 'morphdom'
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'

import { useTheme } from '@/shared/contexts/theme-context'
import { API_BASE_URL } from '@/shared/lib/config'
import { cn } from '@/shared/lib/utils'

import { upgradeAll } from '@/entities/document/wc/markdown/hydrate-all'
import { usePluginManifest } from '@/entities/plugin'

import { ImageModal } from '@/features/edit-document/ui/ImageModal'
import { renderMarkdown } from '@/features/markdown'
import { collectRendererSpecs, addPlaceholderHydration } from '@/features/markdown/lib/add-placeholder-hydration'
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

function ensureTaskContentWrapper(li: HTMLElement, checkbox: HTMLInputElement) {
  const existing = Array.from(li.children).find(
    (child) => child !== checkbox && child.classList.contains('refmd-task-content'),
  ) as HTMLElement | undefined
  if (existing) return existing

  const wrapper = document.createElement('div')
  wrapper.classList.add('refmd-task-content')
  wrapper.dataset.refmdTaskContent = 'true'

  let sibling: ChildNode | null = checkbox.nextSibling
  while (sibling) {
    const nextSibling = sibling.nextSibling
    wrapper.appendChild(sibling)
    sibling = nextSibling
  }

  checkbox.insertAdjacentElement('afterend', wrapper)
  return wrapper
}

function ServerMarkdown({ content, className, documentIdOverride, onTagClick, onToggleTask, taskToggleDisabled }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [html, setHtml] = useState<string>('')
  const [modalImage, setModalImage] = useState<{ src: string; alt?: string } | null>(null)
  const previousHtmlRef = useRef<string>('')
  const { theme } = useTheme()
  const highlightTheme = useMemo(
    () => (theme === 'dark' ? 'one-dark-pro' : 'github-light'),
    [theme],
  )

  // Get plugin manifests for placeholder hydration
  const { plugins } = usePluginManifest()
  const rendererSpecs = useMemo(() => collectRendererSpecs(plugins), [plugins])
  const placeholderKinds = useMemo(
    () => [...new Set(rendererSpecs.map((s) => s.kind))],
    [rendererSpecs]
  )

  const requestRef = useRef<any | null>(null)
  const queuedRef = useRef<{ text: string; override?: string } | null>(null)
  const latestKeyRef = useRef<string>('')

  useEffect(() => () => {
    if (requestRef.current && typeof requestRef.current?.cancel === 'function') {
      try { requestRef.current.cancel() } catch {}
    }
    queuedRef.current = null
  }, [])

  const lastSuccessfulHtmlRef = useRef<string>('')

  const runRender = useCallback(
    async (text: string, override?: string) => {
      const requestKey = `${override ?? ''}::${text}::${highlightTheme}`
      latestKeyRef.current = requestKey

      const apiOrigin = (() => { try { return new URL((API_BASE_URL || '')).origin } catch { return '' } })()
      let token: string | undefined
      try { token = new URLSearchParams(window.location.search).get('token') || undefined } catch {}

      const promise = renderMarkdown(text, {
        flavor: 'doc',
        features: ['gfm', 'highlight'],
        sanitize: true,
        hardbreaks: true,
        // Keep attachment paths as-is (./attachments/xxx) for client-side file map resolution
        absoluteAttachments: false,
        baseOrigin: apiOrigin,
        docId: override,
        token: token,
        theme: highlightTheme,
        placeholderKinds: placeholderKinds.length > 0 ? placeholderKinds : undefined,
      })

      requestRef.current = promise as any

      try {
        const out = await promise
        if (latestKeyRef.current === requestKey) {
          let nextHtml = out?.html || ''

          // Add hydration attributes to placeholders
          const placeholders = out?.placeholders || []
          if (placeholders.length > 0 && rendererSpecs.length > 0) {
            nextHtml = addPlaceholderHydration(nextHtml, placeholders, rendererSpecs, {
              theme: highlightTheme,
              docId: override,
              token,
            })
          }

          lastSuccessfulHtmlRef.current = nextHtml
          setHtml(nextHtml)
        }
      } catch (error: any) {
        if (error?.name === 'AbortError' || error?.message === 'Cancelled') {
          return
        }
        if (latestKeyRef.current === requestKey) {
          setHtml(lastSuccessfulHtmlRef.current)
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
    [highlightTheme, rendererSpecs, placeholderKinds],
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
        onBeforeElUpdated: (fromEl, toEl) => {
          if (fromEl.tagName === 'REFMD-WIKILINK' || fromEl.tagName === 'REFMD-ATTACHMENT') {
            return false
          }
          // Preserve decrypted images - don't let morphdom reset their src
          if (fromEl.tagName === 'IMG' && (fromEl as HTMLImageElement).dataset.decryptedSrc) {
            const fromImg = fromEl as HTMLImageElement
            const toImg = toEl as HTMLImageElement
            const toSrc = toImg.getAttribute('src') || ''
            // Only skip update if the original src (before decryption) matches
            // This preserves the decrypted blob URL while allowing updates if the image actually changed
            if (fromImg.dataset.e2eeProcessedSrc === toSrc || fromImg.dataset.e2eeProcessing === toSrc) {
              return false
            }
          }
          return true
        },
      })
    }
    previousHtmlRef.current = html

    const detachFns: Array<() => void> = []

    try {
      const maybeFns = upgradeAll(el, documentIdOverride)
      if (Array.isArray(maybeFns)) detachFns.push(...maybeFns)
    } catch {}

    const enableTaskToggle = typeof onToggleTask === 'function' && !taskToggleDisabled
    const checkboxes = Array.from(el.querySelectorAll('input[type="checkbox"]')) as HTMLInputElement[]
    for (const checkbox of checkboxes) {
      const li = checkbox.closest('[data-sourcepos]') as HTMLElement | null
      if (li) ensureTaskContentWrapper(li, checkbox)
      if (!enableTaskToggle) continue
      if (checkbox.dataset.refmdTaskInteractive === 'true') continue
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
    const imgs = Array.from(el.querySelectorAll('img')) as HTMLImageElement[]

    // Process images - decrypt E2EE images and replace src with blob URL
    for (const img of imgs) {
      const src = img.getAttribute('src') || ''

      // Skip if already processing this exact src
      if (img.dataset.e2eeProcessing === src) {
        continue
      }

      // Skip if already processed this exact src
      if (img.dataset.e2eeProcessedSrc === src) {
        continue
      }

      const bridge = (window as any).__refmd_file_decryption__

      // Check if this is a logical path (./attachments/xxx) that needs decryption
      if ((src.startsWith('./attachments/') || src.startsWith('attachments/')) && documentIdOverride && bridge?.resolveAndDecrypt) {
        // Mark as processing with the specific src
        img.dataset.e2eeProcessing = src
        img.style.opacity = '0.5'
        img.alt = 'Loading encrypted image...'

        // Capture the original src to verify later
        const originalSrc = src

        bridge.resolveAndDecrypt(src, documentIdOverride)
          .then((result: { blobUrl: string; filename: string; mimeType: string } | null) => {
            // Verify the image still has the same src we started with
            // (morphdom might have reused this element for a different image)
            const currentSrc = img.getAttribute('src') || ''
            const currentProcessing = img.dataset.e2eeProcessing

            // Only apply result if this element still corresponds to the original src
            // Either the src hasn't changed, or the processing marker matches
            if (currentSrc !== originalSrc && currentProcessing !== originalSrc) {
              // Element was reused for a different image, skip this result
              return
            }

            delete img.dataset.e2eeProcessing
            img.dataset.e2eeProcessedSrc = originalSrc
            if (result) {
              img.src = result.blobUrl
              img.alt = result.filename
              img.dataset.decryptedSrc = result.blobUrl
            }
            img.style.opacity = '1'
          })
          .catch(() => {
            // Only clear processing state if it still matches
            if (img.dataset.e2eeProcessing === originalSrc) {
              delete img.dataset.e2eeProcessing
              img.style.opacity = '1'
            }
          })
      }
    }

    // Note: Blob URLs are NOT revoked here because they are cached in blobUrlCache
    // and may be reused across renders. They are cleaned up when clearFileMap is called
    // (e.g., when navigating away from the document).

    detachFns.push(...imgs.map((img) => {
      const handler = (e: Event) => {
        e.preventDefault()
        e.stopPropagation()
        // Use decrypted src if available
        const src = img.dataset.decryptedSrc || img.getAttribute('src') || ''
        setModalImage({ src, alt: img.getAttribute('alt') || undefined })
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
  }, [html, onTagClick, documentIdOverride])

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
