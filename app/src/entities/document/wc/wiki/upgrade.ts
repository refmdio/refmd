export function upgradeWikiLinks(root: Element) {
  const anchors = Array.from(root.querySelectorAll('a.wikilink, a[data-wiki-target], a[href^="#wiki:"]')) as HTMLAnchorElement[]
  for (const a of anchors) {
    if ((a as any)._upgraded) continue
    ;(a as any)._upgraded = true
    const href = a.getAttribute('href') || ''
    const data = a.getAttribute('data-wiki-target') || ''
    const target = data || (href.startsWith('#wiki:') ? href.slice('#wiki:'.length) : '')
    const el = document.createElement('refmd-wikilink') as HTMLElement
    if (target) el.setAttribute('target', target)
    if (href) el.setAttribute('href', href)
    // Detect embed style hint (anchor might contain label like [[id|embed]]) - naive: if class contains 'embed'
    if ((a.className || '').includes('embed')) el.setAttribute('variant', 'embed')
    const text = (a.textContent || '').trim()
    if (text && !text.startsWith('#wiki:')) el.textContent = text
    a.replaceWith(el)
  }
}

