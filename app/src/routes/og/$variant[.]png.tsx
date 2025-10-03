import { createFileRoute } from '@tanstack/react-router'

import { normalizeOgImageVariant, type OgImageVariant } from '@/shared/lib/og'

import { generateOgImage } from '@/server/og'

const FALLBACKS: Record<OgImageVariant, { title: string; subtitle?: string; description?: string; badge?: string; meta?: string }> = {
  default: {
    title: 'RefMD',
    description: 'Collaborative medical documentation, refined.',
    badge: 'RefMD',
    meta: 'refmd.io',
  },
  document: {
    title: 'RefMD Document',
    subtitle: 'Collaborative editing in real time',
    badge: 'Document',
    meta: 'refmd.io',
  },
  'public-document': {
    title: 'Public document on RefMD',
    subtitle: 'Shared knowledge hub',
    badge: 'Public Document',
    meta: 'refmd.io',
  },
  'public-profile': {
    title: 'Public profile on RefMD',
    subtitle: 'Discover shared medical documents',
    badge: 'Public Profile',
    meta: 'refmd.io',
  },
  'share-folder': {
    title: 'Shared folder on RefMD',
    subtitle: 'Secure collaboration',
    badge: 'Shared Folder',
    meta: 'refmd.io',
  },
}

const pickParam = (search: URLSearchParams, key: string) => {
  const value = search.get(key)
  if (!value) return undefined
  return value.trim()
}

export const Route = createFileRoute('/og/$variant.png')({
  server: {
    handlers: {
      GET: async ({ params, request }) => {
        const variant = normalizeOgImageVariant(params['variant.png'])
        const url = new URL(request.url)
        const query = url.searchParams

        const base = FALLBACKS[variant]
        const title = pickParam(query, 'title') ?? base.title
        const subtitle = pickParam(query, 'subtitle') ?? base.subtitle
        const description = pickParam(query, 'description') ?? base.description
        const badge = pickParam(query, 'badge') ?? base.badge
        const meta = pickParam(query, 'meta') ?? base.meta

        try {
          const png = await generateOgImage({ variant, title, subtitle, description, badge, meta })
          return new Response(png, {
            headers: {
              'Content-Type': 'image/png',
              'Cache-Control': 'public, max-age=3600, stale-while-revalidate=86400',
            },
          })
        } catch (error) {
          console.error('Failed to generate OG image', error)
          return new Response('Internal Server Error', { status: 500 })
        }
      },
    },
  },
})
