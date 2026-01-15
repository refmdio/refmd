/**
 * WASM Module Loader
 *
 * Loads plugin WASM modules from the server with caching support.
 */

import type { ManifestItem } from '@/shared/api'
import { API_BASE_URL } from '@/shared/lib/config'

/** Cache name for plugin WASM modules */
const WASM_CACHE_NAME = 'plugin-wasm-v1'

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

/**
 * Get the WASM URL for a plugin.
 *
 * The backend field contains a pre-signed URL path for the WASM module.
 * We prepend the API origin to make it a full URL.
 *
 * @param _pluginId - Plugin identifier (unused, kept for API compatibility)
 * @param manifest - Plugin manifest
 * @returns URL to fetch WASM from
 */
export function getPluginWasmUrl(_pluginId: string, manifest: ManifestItem): string | null {
  // Extract backend from manifest - backend.wasm contains the signed URL path
  const backend = manifest.backend as { wasm?: string } | undefined | null
  const wasmPath = backend?.wasm

  if (!wasmPath) {
    return null
  }

  // If it's already an absolute URL, return as-is
  if (wasmPath.startsWith('http://') || wasmPath.startsWith('https://')) {
    return wasmPath
  }

  // Prepend API origin to the signed path
  const apiOrigin = getApiOrigin()
  return apiOrigin ? `${apiOrigin}${wasmPath}` : wasmPath
}

/**
 * Load plugin WASM with Service Worker caching.
 *
 * @param pluginId - Plugin identifier
 * @param manifest - Plugin manifest
 * @returns URL to the WASM module (from cache or network)
 */
export async function loadPluginWasm(
  pluginId: string,
  manifest: ManifestItem
): Promise<string> {
  const wasmUrl = getPluginWasmUrl(pluginId, manifest)

  if (!wasmUrl) {
    throw new Error(`Plugin ${pluginId} does not have a backend WASM module`)
  }

  // Use Service Worker cache if available
  if (typeof window !== 'undefined' && 'caches' in window) {
    try {
      const cache = await caches.open(WASM_CACHE_NAME)
      const cached = await cache.match(wasmUrl)

      if (cached) {
        // Return cached URL
        return wasmUrl
      }

      // Fetch and cache
      const response = await fetch(wasmUrl)
      if (response.ok) {
        await cache.put(wasmUrl, response.clone())
      }
    } catch {
      // Cache API not available or failed, continue without caching
    }
  }

  return wasmUrl
}

/**
 * Check if a plugin has a backend WASM module.
 */
export function hasPluginWasm(manifest: ManifestItem): boolean {
  const backend = manifest.backend as { wasm?: string } | undefined | null
  return typeof backend?.wasm === 'string' && backend.wasm.length > 0
}

/**
 * Clear the WASM cache.
 */
export async function clearWasmCache(): Promise<void> {
  if (typeof window !== 'undefined' && 'caches' in window) {
    try {
      await caches.delete(WASM_CACHE_NAME)
    } catch {
      // Ignore errors
    }
  }
}

/**
 * Clear cached WASM for a specific plugin.
 */
export async function clearPluginWasmCache(
  pluginId: string,
  manifest: ManifestItem
): Promise<void> {
  const wasmUrl = getPluginWasmUrl(pluginId, manifest)
  if (!wasmUrl) return

  if (typeof window !== 'undefined' && 'caches' in window) {
    try {
      const cache = await caches.open(WASM_CACHE_NAME)
      await cache.delete(wasmUrl)
    } catch {
      // Ignore errors
    }
  }
}
