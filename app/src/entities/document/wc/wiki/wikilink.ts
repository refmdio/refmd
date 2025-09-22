import { DocumentsService } from '@/shared/api'
import type { Document as ApiDocument } from '@/shared/api'

type DocInfo = {
  id: string
  title: string
  type?: string
  path?: string | null
  created_at?: string
  updated_at?: string
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function isUuid(value: string): boolean {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value)
}

function shareToken(): string {
  try { return new URLSearchParams(window.location.search).get('token') || '' } catch { return '' }
}

function typeIcon(type?: string): string {
  const iconType = (type || 'document').toLowerCase()
  const base = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
  if (iconType === 'folder') {
    return `<svg ${base} class="h-4 w-4 text-blue-600"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h10a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>`
  }
  if (iconType === 'scrap') {
    return `<svg ${base} class="h-4 w-4 text-gray-600"><path d="M4 19.5A2.5 2.5 0 0 0 6.5 22H18"/><path d="M20 22V8"/><path d="M20 8 4 4 4 19.5"/><path d="M4 4 14 2 20 8"/></svg>`
  }
  return `<svg ${base} class="h-4 w-4 text-gray-600"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 4v4h6"/></svg>`
}

function badgeClasses(): string {
  return 'inline-flex items-center justify-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap border-transparent bg-secondary text-secondary-foreground'
}

function filePath(path?: string | null): string | null {
  if (!path) return null
  const parts = path.split('/')
  return parts.length > 1 ? parts.slice(1).join('/') : path
}

function relativeTime(date?: string): string {
  if (!date) return ''
  const parsed = new Date(date)
  if (Number.isNaN(parsed.getTime())) return ''
  const diff = Date.now() - parsed.getTime()
  const minute = 60_000
  const hour = 60 * minute
  const day = 24 * hour
  if (diff < minute) return 'just now'
  if (diff < hour) return `${Math.floor(diff / minute)}m ago`
  if (diff < day) return `${Math.floor(diff / hour)}h ago`
  if (diff < day * 7) return `${Math.floor(diff / day)}d ago`
  const y = parsed.getFullYear()
  const m = String(parsed.getMonth() + 1).padStart(2, '0')
  const d = String(parsed.getDate()).padStart(2, '0')
  return `${y}/${m}/${d}`
}

async function fetchDoc(id: string): Promise<DocInfo | null> {
  try {
    const token = shareToken() || undefined
    const data = await DocumentsService.getDocument({ id, token })
    const doc = data as ApiDocument
    return {
      id: String(doc?.id ?? id),
      title: String(doc?.title ?? 'Untitled'),
      type: typeof doc?.type === 'string' ? doc.type : 'document',
      path: typeof doc?.path === 'string' || doc?.path === null ? doc?.path ?? null : null,
      created_at: typeof doc?.created_at === 'string' ? doc.created_at : undefined,
      updated_at: typeof doc?.updated_at === 'string' ? doc.updated_at : undefined,
    }
  } catch {
    return null
  }
}

class RefmdWikiLink extends HTMLElement {
  private static cache = new Map<string, DocInfo | null>()
  private static pending = new Map<string, Promise<DocInfo | null>>()

  connectedCallback() {
    if (!this.dataset.originalLabel) this.dataset.originalLabel = (this.textContent || '').trim()
    this.render()
  }

  static get observedAttributes() { return ['target','variant','href'] }

  attributeChangedCallback() {
    this.render()
  }

  private key(target: string): string {
    return `${target}|${shareToken()}`
  }

  private getCached(target: string) {
    return RefmdWikiLink.cache.get(this.key(target))
  }

  private setCached(target: string, doc: DocInfo | null) {
    RefmdWikiLink.cache.set(this.key(target), doc)
  }

  private async load(target: string) {
    const key = this.key(target)
    if (!RefmdWikiLink.pending.has(key)) {
      RefmdWikiLink.pending.set(key, fetchDoc(target).finally(() => RefmdWikiLink.pending.delete(key)))
    }
    return RefmdWikiLink.pending.get(key)!
  }

  private renderInline(doc: DocInfo | null | undefined, fallback: string) {
    if (doc === null) {
      this.innerHTML = `<span class="inline-flex items-center gap-2 px-3 py-1.5 text-sm border rounded-md bg-muted text-muted-foreground">Not found</span>`
      return
    }
    if (!doc) {
      this.innerHTML = `<span class="text-sm text-muted-foreground">${escapeHtml(fallback)}</span>`
      return
    }
    const path = filePath(doc.path)
    this.innerHTML = `
      <a href="/document/${encodeURIComponent(doc.id)}" class="no-underline hover:no-underline decoration-transparent hover:decoration-transparent">
        <span class="inline-flex items-center gap-2 px-3 py-1.5 text-sm border rounded-md bg-card hover:bg-accent/50 transition-colors">
          <span class="flex-shrink-0">${typeIcon(doc.type)}</span>
          <span class="flex-1 min-w-0">
            <span class="font-medium">${escapeHtml(doc.title || fallback)}</span>
            ${path ? `<span class="text-xs text-muted-foreground ml-2">${escapeHtml(path)}</span>` : ''}
          </span>
        </span>
      </a>
    `
  }

  private renderEmbed(doc: DocInfo | null | undefined, fallback: string) {
    if (doc === null) {
      this.innerHTML = `<div class="border rounded-md px-4 py-3 bg-card text-xs text-muted-foreground">Not found</div>`
      return
    }
    if (!doc) {
      this.innerHTML = `<div class="border rounded-md px-4 py-3 bg-card text-xs text-muted-foreground">Loading…</div>`
      return
    }
    const path = filePath(doc.path)
    const updated = relativeTime(doc.updated_at)
    this.innerHTML = `
      <div class="wikilink-embed">
        <a href="/document/${encodeURIComponent(doc.id)}" class="block no-underline hover:no-underline decoration-transparent hover:decoration-transparent">
          <span class="flex items-center gap-2 px-4 py-3 border rounded-md bg-card hover:bg-accent/50 transition-colors group w-full">
            <span class="flex-shrink-0">${typeIcon(doc.type)}</span>
            <span class="flex-1 min-w-0 flex flex-col justify-center">
              <span class="text-sm font-medium text-foreground truncate" title="${escapeHtml(doc.title || fallback)}">${escapeHtml(doc.title || fallback)}</span>
              ${path ? `<span class="text-xs text-muted-foreground truncate">${escapeHtml(path)}</span>` : ''}
            </span>
            ${updated ? `<span class="flex items-center gap-1 text-xs text-muted-foreground opacity-60 group-hover:opacity-100 transition-opacity h-8"><svg viewBox="0 0 24 24" class="h-3 w-3" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><span>${escapeHtml(updated)}</span></span>` : ''}
            <span class="${badgeClasses()}">${escapeHtml((doc.type || 'document').toUpperCase())}</span>
          </span>
        </a>
      </div>
    `
  }

  async render() {
    const target = (this.getAttribute('target') || '').trim()
    const variant = (this.getAttribute('variant') || 'inline').toLowerCase()
    const inline = variant !== 'embed'
    const fallback = this.dataset.originalLabel || target || 'Untitled'

    if (!target) {
      this.innerHTML = `<span class="text-sm text-muted-foreground">${escapeHtml(fallback)}</span>`
      return
    }

    if (!isUuid(target)) {
      const doc: DocInfo = { id: target, title: fallback || target }
      inline ? this.renderInline(doc, fallback) : this.renderEmbed(doc, fallback)
      return
    }

    const cached = this.getCached(target)
    if (cached !== undefined) {
      inline ? this.renderInline(cached, fallback) : this.renderEmbed(cached, fallback)
      return
    }

    inline ? this.renderInline(undefined as any, fallback) : this.renderEmbed(undefined as any, fallback)

    const doc = await this.load(target)
    this.setCached(target, doc)
    if (!this.isConnected) return
    inline ? this.renderInline(doc, fallback) : this.renderEmbed(doc, fallback)
  }
}

if (!customElements.get('refmd-wikilink')) {
  customElements.define('refmd-wikilink', RefmdWikiLink)
}

export { RefmdWikiLink }
