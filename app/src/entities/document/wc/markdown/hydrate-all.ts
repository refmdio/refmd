import '../attachments/attachment'
import { upgradeAttachments } from '../attachments/upgrade'
import '../wiki/wikilink'
import { upgradeCodeBlocks } from '../code/upgrade'
import { upgradeWikiLinks } from '../wiki/upgrade'

export function upgradeAll(root: Element) {
  upgradeAttachments(root)
  upgradeWikiLinks(root)
  return upgradeCodeBlocks(root)
}

export { upgradeAttachments, upgradeWikiLinks, upgradeCodeBlocks }
