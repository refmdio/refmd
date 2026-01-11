/**
 * Attachments plugin for rehype
 * Rewrites attachment URLs to absolute API paths
 *
 * Comrak compatibility:
 * - ./attachments/xxx -> /api/uploads/{docId}/attachments/xxx
 * - attachments/xxx -> /api/uploads/{docId}/attachments/xxx
 * - Adds ?token=xxx if share token provided
 * - Adds class="file-attachment" to attachment links
 */

import { visit } from 'unist-util-visit'
import type { Plugin } from 'unified'
import type { Root, Element } from 'hast'

export interface AttachmentOptions {
  /** Document ID for URL rewriting */
  docId?: string
  /** Share token for authentication */
  token?: string
  /** Base origin for absolute URLs */
  baseOrigin?: string
  /** Enable absolute URL rewriting (default: false) */
  absoluteAttachments?: boolean
}

function isAttachmentUrl(url: string): boolean {
  return url.startsWith('./attachments/') || url.startsWith('attachments/')
}

function isUploadsUrl(url: string): boolean {
  return url.startsWith('/api/uploads/')
}

function rewriteAttachmentUrl(url: string, options: AttachmentOptions): string | null {
  const { docId, token, baseOrigin, absoluteAttachments } = options

  if (!absoluteAttachments || !docId) {
    return null
  }

  let path: string

  if (url.startsWith('./attachments/')) {
    path = `/api/uploads/${docId}/${url.slice(2)}` // Remove './'
  } else if (url.startsWith('attachments/')) {
    path = `/api/uploads/${docId}/${url}`
  } else if (url.startsWith('/api/uploads/')) {
    path = url
  } else {
    return null
  }

  // Add token if provided
  if (token) {
    const encodedToken = encodeURIComponent(token)
    if (path.includes('?')) {
      path += `&token=${encodedToken}`
    } else {
      path += `?token=${encodedToken}`
    }
  }

  // Add base origin if provided
  if (baseOrigin) {
    const origin = baseOrigin.replace(/\/$/, '')
    return `${origin}${path}`
  }

  return path
}


export const rehypeAttachments: Plugin<[AttachmentOptions?], Root> = (options = {}) => {
  return (tree) => {
    visit(tree, 'element', (node: Element, index: number | undefined, parent) => {
      if (index === undefined || !parent) return

      // Handle links
      if (node.tagName === 'a') {
        const href = node.properties?.href
        if (typeof href !== 'string') return

        if (isAttachmentUrl(href) || isUploadsUrl(href)) {
          const newUrl = rewriteAttachmentUrl(href, options)

          if (newUrl) {
            node.properties = node.properties || {}
            node.properties.href = newUrl
          }

          // Add file-attachment class
          const existingClass = node.properties?.className
          if (Array.isArray(existingClass)) {
            if (!existingClass.includes('file-attachment')) {
              existingClass.push('file-attachment')
            }
          } else if (typeof existingClass === 'string') {
            node.properties.className = [existingClass, 'file-attachment']
          } else {
            node.properties.className = ['file-attachment']
          }
        }
      }

      // Handle images
      if (node.tagName === 'img') {
        const src = node.properties?.src
        if (typeof src !== 'string') return

        if (isAttachmentUrl(src) || isUploadsUrl(src)) {
          const newUrl = rewriteAttachmentUrl(src, options)

          if (newUrl) {
            node.properties = node.properties || {}
            node.properties.src = newUrl
          }
        }
      }
    })
  }
}

export default rehypeAttachments
