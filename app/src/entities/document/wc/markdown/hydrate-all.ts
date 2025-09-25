import '../attachments/attachment'
import { upgradeAttachments } from '../attachments/upgrade'
import '../wiki/wikilink'
import { upgradeCodeBlocks } from '../code/upgrade'
import { upgradePluginHydrators } from '../placeholder/hydrate'
import { upgradeWikiLinks } from '../wiki/upgrade'

export function upgradeAll(root: Element) {
  upgradeAttachments(root)
  upgradeWikiLinks(root)
  upgradePluginHydrators(root)
  return upgradeCodeBlocks(root)
}

export { upgradeAttachments, upgradeWikiLinks, upgradeCodeBlocks }
