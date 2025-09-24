import { API_BASE_URL } from '@/shared/lib/config'

const moduleCache = new Map<string, Promise<any>>()

type HydratorContext = unknown

type HydratorFn = (element: HTMLElement, context: HydratorContext) => void | Promise<void>

function decodeBase64(input: string): string {
  if (!input) return ''
  if (typeof atob === 'function') {
    try {
      return atob(input)
    } catch {
      return ''
    }
  }
  return ''
}

function parseContext(value: string | null): HydratorContext {
  if (!value) return null
  try {
    const decoded = decodeBase64(value)
    return decoded ? JSON.parse(decoded) : null
  } catch (err) {
    console.warn('[hydrate] failed to decode context', err)
    return null
  }
}

function resolveModuleUrl(raw: string | null): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  if (/^https?:\/\//i.test(trimmed)) return trimmed

  const base = (API_BASE_URL && API_BASE_URL.trim()) || undefined
  try {
    if (base) return new URL(trimmed, base).toString()
  } catch {}

  try {
    return new URL(trimmed, window.location.origin).toString()
  } catch {
    return trimmed
  }
}

export function upgradePluginHydrators(root: Element) {
  const nodes = Array.from(
    root.querySelectorAll<HTMLElement>('[data-refmd-placeholder="true"][data-placeholder-hydrate]'),
  )

  for (const element of nodes) {
    if (element.dataset.placeholderHydrated === 'true' || element.dataset.placeholderHydrated === 'pending') {
      continue
    }

    const resolvedUrl = resolveModuleUrl(element.getAttribute('data-placeholder-hydrate'))
    if (!resolvedUrl) continue

    element.dataset.placeholderHydrated = 'pending'

    const exportName = element.getAttribute('data-placeholder-hydrate-export') || 'default'
    const contextAttr = element.getAttribute('data-placeholder-hydrate-context')
    const context = parseContext(contextAttr)

    let loader = moduleCache.get(resolvedUrl)
    if (!loader) {
      loader = import(/* @vite-ignore */ resolvedUrl)
      moduleCache.set(resolvedUrl, loader)
    }

    loader
      .then(async (mod) => {
        const candidate: HydratorFn | undefined = (mod && (mod[exportName] ?? mod.default)) as HydratorFn | undefined
        if (typeof candidate !== 'function') {
          console.warn('[hydrate] module missing export', resolvedUrl, exportName)
          element.dataset.placeholderError = 'missing-export'
          return
        }
        try {
          await candidate(element, context)
          element.dataset.placeholderHydrated = 'true'
        } catch (err) {
          console.error('[hydrate] execution failed', err)
          element.dataset.placeholderError = 'execution'
          element.removeAttribute('data-placeholder-hydrated')
        }
      })
      .catch((err) => {
        console.error('[hydrate] failed to import module', resolvedUrl, err)
        element.dataset.placeholderError = 'import'
        element.removeAttribute('data-placeholder-hydrated')
      })
  }
}

export function __clearHydratorModuleCache() {
  moduleCache.clear()
}
