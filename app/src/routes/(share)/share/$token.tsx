import { createFileRoute, redirect } from '@tanstack/react-router'
import { useEffect } from 'react'

import { buildCanonicalUrl, buildOgImageUrl } from '@/entities/public'
import { browseShare, buildShareSummary } from '@/entities/share'

import { extractShareKeyFromFragment } from '@/features/security'
import { useShareContext } from '@/features/sharing'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import { ShareFolderPage } from '@/widgets/share/ShareFolderPage'

type LoaderData = {
  token: string
  title: string
  items: Array<{ id: string; title: string; path?: string; shareToken?: string; encryptedDek?: string }>
  tree: Array<{ id: string; title: string; parent_id?: string | null; type: string; shareToken?: string; encryptedDek?: string }>
  description: string
}

export const Route = createFileRoute('/(share)/share/$token')({
  staticData: { layout: 'share' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  loader: async ({ params }) => {
    const token = params.token
    const resp = await browseShare(token)
    const treeData = Array.isArray(resp.tree) ? resp.tree : []
    if (treeData.length === 0) {
      throw new Error('Invalid or expired share link.')
    }
    const root = treeData.find((n: any) => !n.parent_id) ?? treeData[0]
    if (root?.type !== 'folder') {
      throw redirect({
        to: '/document/$id',
        params: { id: String(root.id) },
        search: { token, shareScope: 'document' },
      })
    }

    const idMap = new Map(treeData.map((n: any) => [String(n.id), n]))
    const getPath = (nodeId: string): string => {
      const parts: string[] = []
      let cur = idMap.get(nodeId)
      // Support both camelCase (new) and snake_case (legacy) parent_id
      while (cur && (cur.parentId || cur.parent_id)) {
        const parentId = cur.parentId ?? cur.parent_id
        const parent = idMap.get(String(parentId))
        if (!parent) break
        if (String(parent.id) === String(root.id)) break
        parts.push(parent.title)
        cur = parent
      }
      return parts.reverse().join('/')
    }

    const documents = treeData
      .filter((n: any) => n.type === 'document')
      .sort((a: any, b: any) => String(a.title).localeCompare(String(b.title)))
      .map((n: any) => ({
        id: String(n.id),
        title: String(n.title ?? 'Untitled Document'),
        path: getPath(String(n.id)),
        shareToken: n.shareToken ?? undefined,
        encryptedDek: n.encryptedDek ?? undefined,
      }))

    const normalizedTree = treeData.map((n: any) => ({
      id: String(n.id),
      title: String(n.title ?? ''),
      parent_id: n.parentId ? String(n.parentId) : null,
      type: String(n.type ?? ''),
      shareToken: n.shareToken ?? undefined,
      encryptedDek: n.encryptedDek ?? undefined,
    }))
    const summary = buildShareSummary(normalizedTree)

    return {
      token,
      title: String(root.title ?? 'Shared Folder'),
      items: documents,
      tree: normalizedTree,
      description: summary.description,
    } satisfies LoaderData
  },
  head: ({ loaderData, params }) => {
    const data = loaderData as LoaderData | undefined
    if (!data) return {}

    const summary = buildShareSummary(data.tree)
    const canonicalPath = `/share/${encodeURIComponent(params.token)}`
    const { base, url: canonicalUrl } = buildCanonicalUrl(canonicalPath)
    const description = summary.description
    const ogImage = buildOgImageUrl(base, {
      variant: 'share-folder',
      title: summary.folderTitle,
      subtitle: 'Shared via RefMD',
      description: summary.documentCount > 0 ? `${summary.documentCount} documents` : undefined,
      badge: 'Shared Folder',
      meta: 'refmd.io/share',
    })

    const metaTitle = `${summary.folderTitle} • Shared RefMD folder`

    return {
      meta: [
        { title: metaTitle },
        { name: 'description', content: description },
        { property: 'og:title', content: metaTitle },
        { property: 'og:description', content: description },
        { property: 'og:type', content: 'website' },
        { property: 'og:url', content: canonicalUrl },
        { property: 'og:image', content: ogImage },
        { name: 'twitter:card', content: 'summary_large_image' },
        { name: 'twitter:title', content: metaTitle },
        { name: 'twitter:description', content: description },
        { name: 'twitter:image', content: ogImage },
      ],
      links: [{ rel: 'canonical', href: canonicalUrl }],
    }
  },
  component: ShareEntry,
})


function ShareEntry() {
  const { token, items, title, tree } = Route.useLoaderData() as LoaderData
  const { setShareKey, setParentToken, setEncryptedDeks } = useShareContext()

  useEffect(() => {
    // Initialize share context on mount
    const initShareContext = async () => {
      // Set parent token
      setParentToken(token)

      // Extract share key from URL fragment ONCE on mount
      const fragment = typeof window !== 'undefined' ? window.location.hash : ''
      if (fragment) {
        const key = await extractShareKeyFromFragment(fragment)
        if (key) {
          setShareKey(key)
        }
      }

      // Build encryptedDeks map from tree
      const deks = new Map<string, string>()
      for (const node of tree) {
        if (node.encryptedDek) {
          deks.set(node.id, node.encryptedDek)
        }
      }
      setEncryptedDeks(deks)
    }

    initShareContext()
  }, [token, tree, setShareKey, setParentToken, setEncryptedDeks])

  return <ShareFolderPage token={token} title={title} items={items} />
}
