import { Menu, X } from 'lucide-react'
import React, { Suspense, lazy } from 'react'

import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'

import { useAttachmentContext } from '@/features/e2ee'
import { Markdown } from '@/features/edit-document'

import PublicShell from '@/widgets/public/PublicShell'

const TocLazy = lazy(async () => {
  const mod = await import('@/shared/components/toc/Toc')
  return { default: mod.Toc || mod.default }
})

export type PublicDocumentMeta = {
  id: string
  title: string
  parent_id?: string | null
  type: string
  created_at: string
  updated_at: string
  path?: string | null
  workspace_id?: string | null
}

type Props = {
  slug: string
  meta: PublicDocumentMeta
  content: string
}

export default function PublicUserDocumentPage({ slug, meta, content }: Props) {
  const [showToc, setShowToc] = React.useState(false)

  // Initialize attachment context for E2EE file decryption
  useAttachmentContext({
    documentId: meta.id,
    workspaceId: meta.workspace_id,
    setAsDefault: true,
  })

  return (
    <PublicShell pageType="document" title={meta.title} author={{ name: slug }} workspaceSlug={slug} publishedDate={meta.updated_at}>
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
            onClick={() => setShowToc((value) => !value)}
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
