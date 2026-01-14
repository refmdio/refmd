import '../attachments/attachment'
import { upgradeAttachments } from '../attachments/upgrade'
import '../wiki/wikilink'
import { upgradeCodeBlocks } from '../code/upgrade'
import { upgradePluginHydrators } from '../placeholder/hydrate'
import { upgradeWikiLinks } from '../wiki/upgrade'

export function upgradeAll(root: Element, documentId?: string) {
  upgradeAttachments(root, documentId)
  upgradeWikiLinks(root)
  upgradePluginHydrators(root)
  return upgradeCodeBlocks(root)
}

export { upgradeAttachments, upgradeWikiLinks, upgradeCodeBlocks }
