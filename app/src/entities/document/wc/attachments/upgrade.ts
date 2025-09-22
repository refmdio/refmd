export function upgradeAttachments(root: Element) {
  const anchors = Array.from(root.querySelectorAll('a.file-attachment, a[href^="/api/uploads/"], a[href^="./attachments/"], a[href^="attachments/"]')) as HTMLAnchorElement[]
  for (const a of anchors) {
    if ((a as any)._upgraded) continue
    ;(a as any)._upgraded = true
    const href = a.getAttribute('href') || '#'
    const el = document.createElement('refmd-attachment') as HTMLElement
    el.setAttribute('href', href)
    const text = (a.textContent || '').trim()
    if (text && text !== href) el.setAttribute('label', text)
    a.replaceWith(el)
  }
}
