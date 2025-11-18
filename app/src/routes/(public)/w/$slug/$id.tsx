import { createFileRoute } from '@tanstack/react-router'

import {
  buildCanonicalUrl,
  buildOgImageUrl,
  getPublicByWorkspaceAndId,
  getPublicContentByWorkspaceAndId,
} from '@/entities/public'

import PublicUserDocumentPage, { type PublicDocumentMeta } from '@/widgets/public/PublicUserDocumentPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

type LoaderData = {
  slug: string
  meta: PublicDocumentMeta
  content: string
}

export const Route = createFileRoute('/(public)/w/$slug/$id')({
  staticData: { layout: 'public' },
  pendingComponent: () => <RoutePending />, 
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const meta = (await getPublicByWorkspaceAndId(params.slug, params.id)) as unknown as PublicDocumentMeta
    const contentResp = await getPublicContentByWorkspaceAndId(params.slug, params.id)
    const contentValue = typeof (contentResp as any)?.content === 'string' ? String((contentResp as any).content) : ''
    return {
      slug: params.slug,
      meta,
      content: contentValue,
    } satisfies LoaderData
  },
  head: ({ loaderData, params }) => {
    const data = loaderData as LoaderData | undefined
    if (!data) return {}

    const rawTitle = data.meta.title?.trim()
    const title = rawTitle
      ? `${rawTitle} • ${params.slug} on RefMD`
      : `@${params.slug} • RefMD`
    const description = rawTitle
      ? `${rawTitle} — shared by @${params.slug} on RefMD.`
      : `@${params.slug} shared a document on RefMD.`
    const canonicalPath = `/w/${encodeURIComponent(params.slug)}/${data.meta.id}`
    const { base, url: canonicalUrl } = buildCanonicalUrl(canonicalPath)
    const ogImage = buildOgImageUrl(base, {
      variant: 'public-document',
      title: rawTitle || `@${params.slug}`,
      subtitle: `@${params.slug} • Public document`,
      description: 'Shared via RefMD',
      badge: 'Public Document',
      meta: 'refmd.io/public',
    })

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
  component: PublicWorkspaceDocumentRoute,
})

function PublicWorkspaceDocumentRoute() {
  const data = Route.useLoaderData() as LoaderData
  return <PublicUserDocumentPage slug={data.slug} meta={data.meta} content={data.content} />
}
