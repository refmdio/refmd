import { createFileRoute } from '@tanstack/react-router'
import { Menu, X } from 'lucide-react'
import React, { Suspense, lazy } from 'react'

import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'

import { getPublicByOwnerAndId, getPublicContentByOwnerAndId } from '@/entities/public'
import { summarizeMarkdown } from '@/entities/public/lib/summarizeMarkdown'
import { buildCanonicalUrl, buildOgImageUrl } from '@/entities/public/lib/seo'

import { Markdown } from '@/features/edit-document'

import PublicShell from '@/widgets/layouts/PublicShell'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

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
  summary: string
}

export const Route = createFileRoute('/(public)/u/$name/$id')({
  staticData: { layout: 'public' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const meta = (await getPublicByOwnerAndId(params.name, params.id)) as unknown as PublicDoc
    const contentResp = await getPublicContentByOwnerAndId(params.name, params.id)
    const contentValue = typeof (contentResp as any)?.content === 'string' ? String((contentResp as any).content) : ''
    const summary = summarizeMarkdown(
      contentValue,
      `@${params.name} shared a public document on RefMD.`,
    )
    return {
      name: params.name,
      meta,
      content: contentValue,
      summary,
    } satisfies LoaderData
  },
  head: ({ loaderData, params }) => {
    const data = loaderData as LoaderData | undefined
    if (!data) return {}

    const canonicalPath = `/u/${encodeURIComponent(params.name)}/${data.meta.id}`
    const { base, url: canonicalUrl } = buildCanonicalUrl(canonicalPath)
    const ogImage = buildOgImageUrl(base)
    const rawTitle = data.meta.title?.trim()
    const title = rawTitle
      ? `${rawTitle} • ${params.name} on RefMD`
      : `@${params.name} • RefMD`
    const description = data.summary

    return {
      meta: [
        { title },
        { name: 'robots', content: 'index, follow' },
        { name: 'description', content: description },
        { property: 'og:title', content: title },
        { property: 'og:description', content: description },
        { property: 'og:type', content: 'article' },
        { property: 'og:url', content: canonicalUrl },
        { property: 'og:image', content: ogImage },
        { name: 'twitter:card', content: 'summary_large_image' },
        { name: 'twitter:title', content: title },
        { name: 'twitter:description', content: description },
        { name: 'twitter:image', content: ogImage },
      ],
      links: [{ rel: 'canonical', href: canonicalUrl }],
    }
  },
  component: PublicUserDocumentPage,
})

function PublicUserDocumentPage() {
  const { name, meta, content } = Route.useLoaderData() as LoaderData
  const [showToc, setShowToc] = React.useState(false)

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
