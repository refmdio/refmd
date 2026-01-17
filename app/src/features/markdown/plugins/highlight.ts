/**
 * Syntax highlighting plugin for rehype using Shiki
 * Replaces code blocks with highlighted HTML
 *
 * Comrak compatibility:
 * - Wraps highlighted code in <div class="not-prose">...</div>
 * - Default theme: one-dark-pro (similar to OneHalfDark in Syntect)
 */

import type { Root, Element } from 'hast'
import { createHighlighter, type Highlighter, type BundledLanguage } from 'shiki'
import type { Plugin } from 'unified'
import { visit } from 'unist-util-visit'

export interface HighlightOptions {
  /** Theme name (default: 'one-dark-pro') */
  theme?: string
  /** Skip highlighting for these languages (e.g., placeholder kinds) */
  skipLanguages?: Set<string>
}

// Singleton highlighter instance
let highlighterPromise: Promise<Highlighter> | null = null
let loadedLanguages = new Set<string>()

// Common languages to preload
const PRELOAD_LANGUAGES: BundledLanguage[] = [
  'javascript',
  'typescript',
  'jsx',
  'tsx',
  'json',
  'html',
  'css',
  'markdown',
  'python',
  'rust',
  'go',
  'bash',
  'shell',
  'yaml',
  'toml',
  'sql',
  'graphql',
]

async function getHighlighter(): Promise<Highlighter> {
  if (!highlighterPromise) {
    highlighterPromise = createHighlighter({
      themes: ['one-dark-pro', 'github-light', 'github-dark'],
      langs: PRELOAD_LANGUAGES,
    })
  }
  return highlighterPromise
}

async function ensureLanguage(highlighter: Highlighter, lang: string): Promise<boolean> {
  if (loadedLanguages.has(lang)) {
    return true
  }

  try {
    const languages = highlighter.getLoadedLanguages()
    if (languages.includes(lang as BundledLanguage)) {
      loadedLanguages.add(lang)
      return true
    }

    // Try to load the language dynamically
    await highlighter.loadLanguage(lang as BundledLanguage)
    loadedLanguages.add(lang)
    return true
  } catch {
    // Language not available, will use plaintext
    return false
  }
}

function getCodeContent(node: Element): string {
  return node.children
    .map((child) => {
      if (child.type === 'text') return child.value
      if (child.type === 'element') return getCodeContent(child)
      return ''
    })
    .join('')
}

function getLanguageFromClass(className: unknown): string | null {
  if (!className || !Array.isArray(className)) return null

  const langClass = className.find(
    (c): c is string => typeof c === 'string' && c.startsWith('language-')
  )

  if (!langClass) return null
  return langClass.slice('language-'.length).toLowerCase()
}

export const rehypeHighlight: Plugin<[HighlightOptions?], Root> = (options) => {
  const theme = options?.theme || 'one-dark-pro'
  const skipLanguages = options?.skipLanguages || new Set<string>()

  return async (tree) => {
    const highlighter = await getHighlighter()

    // Collect all code blocks to process
    const codeBlocks: Array<{
      node: Element
      parent: Element
      index: number
      lang: string
      code: string
    }> = []

    visit(tree, 'element', (node: Element, index: number | undefined, parent) => {
      if (index === undefined || !parent) return
      if (node.tagName !== 'pre') return

      const codeChild = node.children.find(
        (child): child is Element => child.type === 'element' && child.tagName === 'code'
      )

      if (!codeChild) return

      const lang = getLanguageFromClass(codeChild.properties?.className)
      if (!lang) return

      // Skip if this language is handled by placeholders
      if (skipLanguages.has(lang)) return

      const code = getCodeContent(codeChild)

      codeBlocks.push({
        node,
        parent: parent as Element,
        index,
        lang,
        code,
      })
    })

    // Process each code block
    for (const block of codeBlocks) {
      const langAvailable = await ensureLanguage(highlighter, block.lang)
      const effectiveLang = langAvailable ? block.lang : 'text'

      try {
        // Use codeToHast to get proper HAST nodes instead of raw HTML
        const hast = highlighter.codeToHast(block.code, {
          lang: effectiveLang,
          theme,
        })

        // The result is a root node with a single pre element
        // Extract the pre element and wrap it in a not-prose div
        const preElement = hast.children[0] as Element

        // Wrap in not-prose div like Comrak does
        const wrapper: Element = {
          type: 'element',
          tagName: 'div',
          properties: { class: 'not-prose' },
          children: [preElement],
        }

        // Replace the original pre element with the wrapped highlighted version
        block.parent.children[block.index] = wrapper
      } catch (error) {
        // If highlighting fails, leave the code block as-is
        console.warn(`Failed to highlight ${block.lang}:`, error)
      }
    }
  }
}

/**
 * Pre-initialize the highlighter (call on app startup for better UX)
 */
export async function initHighlighter(): Promise<void> {
  await getHighlighter()
}

export default rehypeHighlight
