import { createFileRoute } from '@tanstack/react-router'

import { buildCanonicalUrl, buildOgImageUrl, listWorkspacePublicDocuments } from '@/entities/public'

import PublicUserListPage from '@/widgets/public/PublicUserListPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

type Summary = { id: string; title: string; updated_at: string; published_at: string }

type LoaderData = {
  slug: string
  items: Summary[]
}

export const Route = createFileRoute('/(public)/w/$slug/')({
  staticData: { layout: 'public' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const items = await listWorkspacePublicDocuments(params.slug)
    return { slug: params.slug, items: items as Summary[] } satisfies LoaderData
  },
  head: ({ loaderData, params }) => {
    const data = loaderData as LoaderData | undefined
    if (!data) return {}

    const canonicalPath = `/w/${encodeURIComponent(params.slug)}`
    const { base, url: canonicalUrl } = buildCanonicalUrl(canonicalPath)
    const total = data.items.length
    const hasItems = total > 0
    const title = hasItems
      ? `@${params.slug} • Public documents on RefMD`
      : `@${params.slug} • RefMD`
    const description = hasItems
      ? `Browse ${total} public ${total === 1 ? 'document' : 'documents'} from @${params.slug} on RefMD.`
      : `@${params.slug} has not published any public documents on RefMD yet.`

    const ogImage = buildOgImageUrl(base, {
      variant: 'public-profile',
      title: `@${params.slug}`,
      subtitle: 'Public documents on RefMD',
      description: hasItems ? 'Shared by the community' : 'RefMD profile',
      badge: 'Public Profile',
      meta: 'refmd.io/public',
    })

    return {
      meta: [
        { title },
        { name: 'robots', content: 'index, follow' },
        { name: 'description', content: description },
        { property: 'og:title', content: title },
        { property: 'og:description', content: description },
        { property: 'og:type', content: 'profile' },
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
  component: PublicWorkspaceRoute,
})

function PublicWorkspaceRoute() {
  const { slug, items } = Route.useLoaderData() as LoaderData
  return <PublicUserListPage slug={slug} items={items} />
}
