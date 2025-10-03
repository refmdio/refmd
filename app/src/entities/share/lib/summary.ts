const PATH_SEPARATOR = ' / '

type ShareTreeItem = {
  id: string
  title: string
  parent_id?: string | null
  type: string
}

type ShareTree = Array<ShareTreeItem>

type ShareSummary = {
  folderTitle: string
  documentCount: number
  description: string
  documentTitles: string
}

export function buildShareSummary(tree: ShareTree): ShareSummary {
  if (!Array.isArray(tree) || tree.length === 0) {
    return {
      folderTitle: 'Shared Folder',
      documentCount: 0,
      description: 'Shared folder on RefMD.',
      documentTitles: '',
    }
  }

  const root = tree.find((node) => !node.parent_id) ?? tree[0]
  const folderTitle = (root?.title ?? 'Shared Folder').trim() || 'Shared Folder'

  const documents = tree.filter((node) => node.type === 'document')
  const documentTitles = documents
    .map((doc) => (doc.title ?? 'Untitled document').trim())
    .filter(Boolean)
  const documentCount = documentTitles.length

  const description = documentCount > 0
    ? `Shared folder “${folderTitle}” with ${documentCount} ${documentCount === 1 ? 'document' : 'documents'} on RefMD.`
    : `Shared folder “${folderTitle}” on RefMD.`

  return {
    folderTitle,
    documentCount,
    description,
    documentTitles: documentTitles.join(PATH_SEPARATOR),
  }
}
