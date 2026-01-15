/**
 * Add hydration attributes to placeholder elements
 * This is needed because the client-side markdown renderer creates placeholders
 * but doesn't add the hydration metadata that tells the hydrator where to load modules from.
 */

import type { ManifestItem } from '@/shared/api'
import { API_BASE_URL } from '@/shared/lib/config'

/**
 * Get the API origin for plugin asset URLs
 */
function getApiOrigin(): string {
  try {
    if (API_BASE_URL) {
      return new URL(API_BASE_URL).origin
    }
  } catch {
    // Fallback to current origin
  }
  if (typeof window !== 'undefined') {
    return window.location.origin
  }
  return ''
}

interface RendererSpec {
  kind: string
  pluginId: string
  pluginVersion: string
  scope: string
  hydrate?: {
    /** Signed URL path from the server */
    module: string
    export?: string
  }
}

/**
 * Extract renderer specs from plugin manifests
 * The manifest's renderers[].hydrate.module contains pre-signed URLs from the server
 */
export function collectRendererSpecs(manifests: ManifestItem[]): RendererSpec[] {
  const specs: RendererSpec[] = []

  for (const manifest of manifests) {
    const renderers = (manifest as any)?.renderers
    if (!Array.isArray(renderers)) continue

    for (const renderer of renderers) {
      const kind = renderer?.kind
      if (typeof kind !== 'string' || !kind.trim()) continue

      const hydrate = renderer?.hydrate
      if (!hydrate || typeof hydrate !== 'object') continue

      // The module URL should be pre-signed by the server
      const module = hydrate?.module
      if (typeof module !== 'string' || !module.trim()) continue

      specs.push({
        kind: kind.trim().toLowerCase(),
        pluginId: manifest.id,
        pluginVersion: manifest.version || 'dev',
        scope: (manifest as any)?.scope || 'global',
        hydrate: {
          module: module.trim(),
          export: typeof hydrate.export === 'string' ? hydrate.export : undefined,
        },
      })
    }
  }

  return specs
}

/**
 * Get the hydration module URL (pre-signed by server)
 */
function getHydrateUrl(spec: RendererSpec): string {
  const modulePath = spec.hydrate!.module

  // If it's already an absolute URL, return as-is
  if (modulePath.startsWith('http://') || modulePath.startsWith('https://')) {
    return modulePath
  }

  // Prepend API origin to the signed path
  const apiOrigin = getApiOrigin()
  return apiOrigin ? `${apiOrigin}${modulePath}` : modulePath
}

/**
 * Build hydration context as base64-encoded JSON
 */
function buildHydrateContext(
  placeholderId: string,
  kind: string,
  code: string,
  spec: RendererSpec,
  options?: { theme?: string; docId?: string; token?: string }
): string {
  const context = {
    request: {
      kind,
      id: placeholderId,
      code,
      options: {
        theme: options?.theme,
        doc_id: options?.docId,
        token: options?.token,
      },
    },
    plugin: {
      id: spec.pluginId,
      version: spec.pluginVersion,
      scope: spec.scope,
    },
  }

  try {
    return btoa(JSON.stringify(context))
  } catch {
    return ''
  }
}

/**
 * Add hydration attributes to placeholder elements in HTML string
 *
 * @param html - The rendered HTML with placeholder divs
 * @param placeholders - Array of placeholder items with code content
 * @param specs - Renderer specs from plugin manifests
 * @param options - Additional options for context
 * @returns Modified HTML with hydration attributes added
 */
export function addPlaceholderHydration(
  html: string,
  placeholders: Array<{ kind: string; id: string; code: string }>,
  specs: RendererSpec[],
  options?: { theme?: string; docId?: string; token?: string }
): string {
  if (!placeholders.length || !specs.length) return html

  // Build a map of kind -> spec (first matching spec wins)
  const specByKind = new Map<string, RendererSpec>()
  for (const spec of specs) {
    if (!specByKind.has(spec.kind)) {
      specByKind.set(spec.kind, spec)
    }
  }

  let result = html

  for (const placeholder of placeholders) {
    const spec = specByKind.get(placeholder.kind.toLowerCase())
    if (!spec || !spec.hydrate) continue

    const hydrateUrl = getHydrateUrl(spec)
    const exportName = spec.hydrate.export || 'default'
    const context = buildHydrateContext(
      placeholder.id,
      placeholder.kind,
      placeholder.code,
      spec,
      options
    )

    // Find the placeholder div and add attributes
    const needle = `data-placeholder-id="${placeholder.id}"`
    const idx = result.indexOf(needle)
    if (idx === -1) continue

    // Find the closing > of the opening tag
    const afterNeedle = result.slice(idx + needle.length)
    const closeIdx = afterNeedle.indexOf('>')
    if (closeIdx === -1) continue

    const insertPos = idx + needle.length + closeIdx

    // Build attribute string
    const attrs = ` data-placeholder-hydrate="${escapeHtml(hydrateUrl)}" data-placeholder-hydrate-export="${escapeHtml(exportName)}" data-placeholder-hydrate-context="${escapeHtml(context)}" data-placeholder-plugin="${escapeHtml(spec.pluginId)}" data-placeholder-version="${escapeHtml(spec.pluginVersion)}" data-placeholder-scope="${escapeHtml(spec.scope)}"`

    result = result.slice(0, insertPos) + attrs + result.slice(insertPos)
  }

  return result
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
