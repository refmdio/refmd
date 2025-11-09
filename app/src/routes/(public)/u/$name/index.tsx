import { createFileRoute } from '@tanstack/react-router'

import { buildCanonicalUrl, buildOgImageUrl, listUserPublicDocuments } from '@/entities/public'

import PublicUserListPage from '@/widgets/public/PublicUserListPage'
import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

type Summary = { id: string; title: string; updated_at: string; published_at: string }

type LoaderData = {
  name: string
  items: Summary[]
}

export const Route = createFileRoute('/(public)/u/$name/')({
  staticData: { layout: 'public' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const items = await listUserPublicDocuments(params.name)
    return { name: params.name, items: items as Summary[] } satisfies LoaderData
  },
  head: ({ loaderData, params }) => {
    const data = loaderData as LoaderData | undefined
    if (!data) return {}

    const canonicalPath = `/u/${encodeURIComponent(params.name)}`
    const { base, url: canonicalUrl } = buildCanonicalUrl(canonicalPath)
    const total = data.items.length
    const hasItems = total > 0
    const title = hasItems
      ? `@${params.name} • Public documents on RefMD`
      : `@${params.name} • RefMD`
    const description = hasItems
      ? `Browse ${total} public ${total === 1 ? 'document' : 'documents'} from @${params.name} on RefMD.`
      : `@${params.name} has not published any public documents on RefMD yet.`

    const ogImage = buildOgImageUrl(base, {
      variant: 'public-profile',
      title: `@${params.name}`,
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
  component: PublicUserRoute,
})

function PublicUserRoute() {
  const { name, items } = Route.useLoaderData() as LoaderData
  return <PublicUserListPage name={name} items={items} />
}
