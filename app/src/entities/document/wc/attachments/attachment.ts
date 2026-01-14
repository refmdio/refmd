/**
 * RefMD Attachment Web Component
 *
 * Displays file attachments with download capability and preview support.
 * Integrates with E2EE for encrypted file decryption.
 */

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function extFromUrl(url: string): string {
  try {
    const path = url.split('?')[0]
    const segs = path.split('/')
    // Remove .rme extension if present
    let name = decodeURIComponent(segs[segs.length - 1] || '')
    if (name.endsWith('.rme')) name = name.slice(0, -4)
    return name.split('.').pop()?.toLowerCase() || ''
  } catch {
    return ''
  }
}

function fileName(url: string): string {
  try {
    const path = url.split('?')[0]
    const segs = path.split('/')
    let name = decodeURIComponent(segs[segs.length - 1] || '')
    // Remove .rme extension for display
    if (name.endsWith('.rme')) name = name.slice(0, -4)
    return name
  } catch {
    return url
  }
}

function iconSvg(ext: string): { svg: string; color: string } {
  const base = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
  const make = (path: string, color: string) => ({ svg: `<svg ${base} class="h-4 w-4">${path}</svg>`, color })
  if (['jpg','jpeg','png','gif','webp','svg','bmp'].includes(ext)) return make('<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 15-5-5L5 21"/>', 'text-green-600')
  if (['pdf','doc','docx','txt','rtf','xls','xlsx','ppt','pptx'].includes(ext)) return make('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>', 'text-red-600')
  if (['js','ts','jsx','tsx','html','css','scss','json','xml','yaml','yml','md','py','java','cpp','c','php','rb','go','rs','swift'].includes(ext)) return make('<path d="M10 6H6a2 2 0 0 0-2 2v4"/><path d="M20 10V8a2 2 0 0 0-2-2h-4"/><path d="M4 14v2a2 2 0 0 0 2 2h4"/><path d="M14 18h4a2 2 0 0 0 2-2v-2"/><path d="m9 9 6 6"/>', 'text-blue-600')
  if (['zip','rar','7z','tar','gz','bz2'].includes(ext)) return make('<path d="M4 3h7v5H4z"/><path d="M4 12h16v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z"/><path d="M11 7h2"/><path d="M11 11h2"/><path d="M13 7v8"/>', 'text-purple-600')
  if (['mp4','avi','mov','wmv','flv','webm','mkv'].includes(ext)) return make('<rect x="2" y="7" width="15" height="10" rx="2"/><path d="M22 7v10l-5-3V10z"/>', 'text-orange-600')
  if (['mp3','wav','flac','aac','ogg','wma'].includes(ext)) return make('<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>', 'text-pink-600')
  return make('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>', 'text-gray-600')
}

function downloadSvg(): string {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-3 w-3"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>'
}

function loadingSvg(): string {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-3 w-3 animate-spin"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>'
}

/**
 * Get decryption bridge from global
 */
function getDecryptionBridge(): {
  resolveAndDecrypt: (logicalPath: string, documentId: string) => Promise<{ blobUrl: string; filename: string; mimeType: string } | null>
  revokeBlobUrl: (url: string) => void
} | null {
  if (typeof window === 'undefined') return null
  return (window as any).__refmd_file_decryption__ ?? null
}

const canUseCustomElements =
  typeof globalThis !== 'undefined' &&
  typeof (globalThis as any).HTMLElement !== 'undefined' &&
  typeof (globalThis as any).customElements !== 'undefined'

if (canUseCustomElements) {
  class RefmdAttachment extends (globalThis as any).HTMLElement {
    private previewOpen = false
    private decryptedBlobUrl: string | null = null
    private decryptedFilename: string | null = null
    private isDecrypting = false
    private decryptError: string | null = null

    connectedCallback() {
      if (!this.dataset.label) this.dataset.label = (this.getAttribute('label') || '').trim()
      this.render()
    }

    disconnectedCallback() {
      // Cleanup blob URL when element is removed
      if (this.decryptedBlobUrl) {
        const bridge = getDecryptionBridge()
        bridge?.revokeBlobUrl(this.decryptedBlobUrl)
        this.decryptedBlobUrl = null
      }
    }

    static get observedAttributes() { return ['href','label','data-document-id'] }

    attributeChangedCallback() {
      this.render()
    }

    private async handleDownload(e: MouseEvent, href: string, label: string) {
      e.preventDefault()
      e.stopPropagation()

      // If already decrypted, use the cached blob
      if (this.decryptedBlobUrl) {
        this.triggerDownload(this.decryptedBlobUrl, this.decryptedFilename || label)
        return
      }

      const documentId = this.getAttribute('data-document-id')
      const bridge = getDecryptionBridge()
      if (!bridge || !documentId) {
        this.decryptError = 'Decryption not available'
        this.render()
        return
      }

      // Show loading state
      this.isDecrypting = true
      this.decryptError = null
      this.render()

      try {
        const result = await bridge.resolveAndDecrypt(href, documentId)
        if (result) {
          this.decryptedBlobUrl = result.blobUrl
          this.decryptedFilename = result.filename
          this.triggerDownload(result.blobUrl, result.filename)
        } else {
          throw new Error('Decryption failed')
        }
      } catch (err) {
        console.error('[E2EE] Download failed:', err)
        this.decryptError = 'Download failed'
      } finally {
        this.isDecrypting = false
        this.render()
      }
    }

    private triggerDownload(url: string, filename: string) {
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
    }

    private async handlePreviewOpen(href: string) {
      // If already decrypted, just toggle
      if (this.decryptedBlobUrl) {
        this.previewOpen = !this.previewOpen
        this.render()
        return
      }

      const documentId = this.getAttribute('data-document-id')
      const bridge = getDecryptionBridge()
      if (!bridge || !documentId) {
        this.decryptError = 'Decryption not available'
        this.previewOpen = true
        this.render()
        return
      }

      // Decrypt for preview
      this.isDecrypting = true
      this.decryptError = null
      this.previewOpen = true
      this.render()

      try {
        const result = await bridge.resolveAndDecrypt(href, documentId)
        if (result) {
          this.decryptedBlobUrl = result.blobUrl
          this.decryptedFilename = result.filename
        } else {
          throw new Error('Decryption failed')
        }
      } catch (err) {
        console.error('[E2EE] Preview decryption failed:', err)
        this.decryptError = 'Decryption failed'
      } finally {
        this.isDecrypting = false
        this.render()
      }
    }

    render() {
      const href = this.getAttribute('href') || '#'
      const labelAttr = (this.getAttribute('label') || this.dataset.label || '').trim()
      const displayFilename = this.decryptedFilename || labelAttr || fileName(href)
      const label = displayFilename
      const ext = extFromUrl(label)
      const isFile = href.includes('/api/uploads/') || href.startsWith('./attachments/') || href.startsWith('./')

      if (!isFile) {
        this.innerHTML = `<a href="${href}" class="text-primary hover:underline">${escapeHtml(label || href)}</a>`
        return
      }

      const { svg: icon, color } = iconSvg(ext)
      const badge = ext ? `<span class="inline-flex items-center justify-center rounded-md border px-2 py-0.5 text-xs font-medium border-transparent bg-secondary text-secondary-foreground">${escapeHtml(ext.toUpperCase())}</span>` : ''
      const previewable = ['mp3','wav','flac','aac','ogg','wma','mp4','avi','mov','wmv','flv','webm','mkv','pdf'].includes(ext)
      if (!previewable) this.previewOpen = false

      const downloadIcon = this.isDecrypting ? loadingSvg() : downloadSvg()
      const preview = this.previewOpen && previewable ? this.previewContent(ext) : ''

      this.innerHTML = `
        <div class="w-full">
          <span data-refmd-attachment-card class="flex items-center gap-2 px-4 py-3 border rounded-md bg-card hover:bg-accent/50 transition-colors group file-attachment w-full${previewable ? ' cursor-pointer' : ''}">
            <span class="flex-shrink-0 ${color}">${icon}</span>
            <span class="text-sm font-medium text-foreground flex-1" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
            ${badge}
            <button data-refmd-attachment-download class="h-8 w-8 ml-auto opacity-60 hover:opacity-100 inline-flex items-center justify-center border-0 bg-transparent cursor-pointer" title="Download file" ${this.isDecrypting ? 'disabled' : ''}>
              ${downloadIcon}
            </button>
          </span>
          ${preview}
        </div>
      `

      const download = this.querySelector('[data-refmd-attachment-download]') as HTMLButtonElement | null
      download?.addEventListener('click', (e) => this.handleDownload(e, href, label))

      if (!previewable) return

      const card = this.querySelector('[data-refmd-attachment-card]') as HTMLElement | null
      card?.addEventListener('click', (e) => {
        // Don't toggle preview if clicking download button
        const target = e.target as HTMLElement
        if (target.closest('[data-refmd-attachment-download]')) return
        this.handlePreviewOpen(href)
      })
    }

    private previewContent(ext: string): string {
      if (this.isDecrypting) {
        return `<div class="mt-3 p-4 border rounded-md bg-background flex items-center justify-center text-muted-foreground">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-5 w-5 animate-spin mr-2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          Decrypting...
        </div>`
      }

      if (this.decryptError || !this.decryptedBlobUrl) {
        return `<div class="mt-3 p-4 border rounded-md bg-destructive/10 text-destructive text-sm">
          Failed to decrypt file. The file may be corrupted or you may not have access.
        </div>`
      }

      const src = this.decryptedBlobUrl

      if (['mp3','wav','flac','aac','ogg','wma'].includes(ext)) {
        return `<div class="mt-3 p-4 border rounded-md bg-background"><audio controls class="w-full" src="${src}"></audio></div>`
      }
      if (['mp4','avi','mov','wmv','flv','webm','mkv'].includes(ext)) {
        return `<div class="mt-3 p-4 border rounded-md bg-background"><video controls class="w-full rounded" src="${src}"></video></div>`
      }
      // PDF
      return `<div class="mt-3 p-4 border rounded-md bg-background"><iframe class="w-full h-[600px] border-0" src="${src}" title="PDF Viewer"></iframe></div>`
    }
  }

  if (!(globalThis as any).customElements.get('refmd-attachment')) {
    (globalThis as any).customElements.define('refmd-attachment', RefmdAttachment)
  }
}

export {}
