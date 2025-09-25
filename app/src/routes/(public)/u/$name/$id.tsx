import { createFileRoute } from '@tanstack/react-router'
import { Menu, X } from 'lucide-react'
import React, { Suspense, lazy } from 'react'

import type { CancelablePromise } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'

import { getPublicByOwnerAndId, getPublicContentByOwnerAndId } from '@/entities/public'

import { Markdown } from '@/features/edit-document'

import PublicShell from '@/widgets/layouts/PublicShell'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import { OpenGraphService } from '@/shared/api'

const TocLazy = lazy(async () => {
  const m = await import('@/shared/components/toc/Toc')
  return { default: m.Toc || m.default }
})

type PublicDoc = {
  id: string
  title: string
  parent_id?: string | null
  type: string
  created_at: string
  updated_at: string
  path?: string | null
}

type LoaderData = {
  name: string
  meta: PublicDoc
  content: string
}

export const Route = createFileRoute('/(public)/u/$name/$id')({
  staticData: { layout: 'public' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const meta = (await getPublicByOwnerAndId(params.name, params.id)) as unknown as PublicDoc
    const contentResp = await getPublicContentByOwnerAndId(params.name, params.id)
    const contentValue = typeof (contentResp as any)?.content === 'string' ? String((contentResp as any).content) : ''
    return {
      name: params.name,
      meta,
      content: contentValue,
    } satisfies LoaderData
  },
  component: PublicUserDocumentPage,
})

function PublicUserDocumentPage() {
  const { name, meta, content } = Route.useLoaderData() as LoaderData
  const [showToc, setShowToc] = React.useState(false)
  React.useEffect(() => {
    if (typeof document === 'undefined') return
    let disposed = false
    const cleanupFns: Array<() => void> = []
    const originalTitle = document.title
    let request: CancelablePromise<string> | null = null

    const applyMetaTag = (attr: 'name' | 'property', key: string, value: string | null | undefined) => {
      if (!key || !value) return
      const selector = attr === 'name' ? `meta[name="${key}"]` : `meta[property="${key}"]`
      const existing = document.head.querySelector(selector) as HTMLMetaElement | null
      if (existing) {
        const prev = existing.getAttribute('content')
        existing.setAttribute('content', value)
        cleanupFns.push(() => {
          if (!existing.parentElement) return
          if (prev == null) existing.removeAttribute('content')
          else existing.setAttribute('content', prev)
        })
      } else {
        const metaEl = document.createElement('meta')
        metaEl.setAttribute(attr, key)
        metaEl.setAttribute('content', value)
        document.head.appendChild(metaEl)
        cleanupFns.push(() => {
          if (metaEl.parentElement) {
            document.head.removeChild(metaEl)
          }
        })
      }
    }

    const applyLinkTag = (rel: string, href: string | null | undefined) => {
      if (!rel || !href) return
      const selector = `link[rel="${rel}"]`
      const existing = document.head.querySelector(selector) as HTMLLinkElement | null
      if (existing) {
        const prev = existing.getAttribute('href')
        existing.setAttribute('href', href)
        cleanupFns.push(() => {
          if (!existing.parentElement) return
          if (prev == null) existing.removeAttribute('href')
          else existing.setAttribute('href', prev)
        })
      } else {
        const linkEl = document.createElement('link')
        linkEl.setAttribute('rel', rel)
        linkEl.setAttribute('href', href)
        document.head.appendChild(linkEl)
        cleanupFns.push(() => {
          if (linkEl.parentElement) {
            document.head.removeChild(linkEl)
          }
        })
      }
    }

    const applyOgDocument = (htmlString: string) => {
      const parser = new DOMParser()
      const parsed = parser.parseFromString(htmlString, 'text/html')
      const parseError = parsed.querySelector('parsererror')
      if (parseError) {
        throw new Error('Failed to parse OpenGraph response')
      }
      const ogTitle = parsed.querySelector('head > title')?.textContent?.trim()
      if (ogTitle) {
        document.title = ogTitle
      }
      parsed.querySelectorAll('head meta[name], head meta[property]').forEach((metaEl) => {
        const nameAttr = metaEl.getAttribute('name')
        const propAttr = metaEl.getAttribute('property')
        const contentAttr = metaEl.getAttribute('content')
        if (nameAttr) applyMetaTag('name', nameAttr, contentAttr)
        else if (propAttr) applyMetaTag('property', propAttr, contentAttr)
      })
      const canonical = parsed.querySelector('head link[rel="canonical"]')?.getAttribute('href')
      applyLinkTag('canonical', canonical)
    }

    if (meta.title) {
      document.title = `${meta.title} • RefMD`
    }

    ;(async () => {
      try {
        request = OpenGraphService.publicDocumentOg({ name, id: meta.id })
        const html = await request
        if (disposed) return
        applyOgDocument(html)
      } catch (error) {
        if (disposed) {
          return
        }
        console.warn('[public-og] failed to apply OpenGraph metadata', error)
      }
    })()

    return () => {
      disposed = true
      try {
        request?.cancel?.()
      } catch {}
      for (let i = cleanupFns.length - 1; i >= 0; i--) {
        try {
          cleanupFns[i]()
        } catch {}
      }
      document.title = originalTitle
    }
  }, [name, meta.id, meta.title])

  return (
    <PublicShell pageType="document" title={meta.title} author={{ name }} publishedDate={meta.updated_at}>
      <section className="relative space-y-6">
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1.2fr)_300px]">
          <article className="min-w-0 overflow-hidden rounded-none border-none bg-transparent shadow-none sm:rounded-3xl sm:border sm:border-border/70 sm:bg-card/90 sm:shadow-sm sm:backdrop-blur sm:supports-[backdrop-filter]:bg-card/75">
            <Markdown
              content={content}
              isPublic
              className="prose prose-neutral dark:prose-invert max-w-none px-4 py-6 sm:px-6 sm:py-8 lg:px-8 lg:py-10"
              documentIdOverride={meta.id}
            />
          </article>
          <aside className="hidden lg:block">
            <div className="sticky top-28 space-y-4">
              <Card className="rounded-2xl border-border/60 bg-card/90 p-0 text-sm text-muted-foreground shadow-sm">
                <Suspense fallback={<div className="px-4 py-3 text-xs text-muted-foreground/70">Loading ToC…</div>}>
                  <TocLazy contentSelector=".markdown-preview" />
                </Suspense>
              </Card>
            </div>
          </aside>
        </div>

        <div className="lg:hidden">
          <Button
            onClick={() => setShowToc((v) => !v)}
            size="icon"
            variant="outline"
            className="fixed bottom-6 right-6 h-12 w-12 rounded-full border-border/70 bg-background/90 shadow-lg backdrop-blur"
          >
            {showToc ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
          {showToc && (
            <div className="fixed bottom-[6.5rem] right-6 z-50 max-w-[90vw] overflow-hidden rounded-2xl border border-border/80 bg-background/95 shadow-2xl backdrop-blur">
              <div className="max-h-[60vh] overflow-auto px-4 py-3 text-sm">
                <Suspense fallback={<div className="text-xs text-muted-foreground/70">Loading ToC…</div>}>
                  <TocLazy contentSelector=".markdown-preview" small floating onItemClick={() => setShowToc(false)} />
                </Suspense>
              </div>
              <div className="flex justify-end border-t border-border/60 px-2 py-2">
                <Button onClick={() => setShowToc(false)} size="sm" variant="ghost" className="h-8 px-3 text-xs">
                  Close
                </Button>
              </div>
            </div>
          )}
        </div>
      </section>
    </PublicShell>
  )
}
