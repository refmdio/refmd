import { Extension } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import {
  autocompletion,
  CompletionContext,
  CompletionResult,
  Completion,
} from '@codemirror/autocomplete'

import { listDocuments } from '@/entities/document'

type SearchResult = {
  id: string
  title: string
  document_type: string
  path?: string | null
  updated_at?: string
}

async function wikiLinkCompletionSource(
  context: CompletionContext
): Promise<CompletionResult | null> {
  // Match [[, ![[, or @[[ patterns
  const wiki = context.matchBefore(/\[\[[^\]]*$/)
  const embed = context.matchBefore(/!\[\[[^\]]*$/)
  const mention = context.matchBefore(/@\[\[[^\]]*$/)
  const match = wiki || embed || mention
  if (!match) return null

  // Extract the prefix and query
  const text = match.text
  let prefix: string
  let query: string

  if (text.startsWith('![[')) {
    prefix = '![['
    query = text.slice(3)
  } else if (text.startsWith('@[[')) {
    prefix = '@[['
    query = text.slice(3)
  } else {
    prefix = '[['
    query = text.slice(2)
  }

  // Check if ]] already exists after cursor
  const line = context.state.doc.lineAt(context.pos)
  const after = context.state.sliceDoc(context.pos, line.to)
  const hasClosing = after.startsWith(']]')

  // Fetch documents
  let items: SearchResult[] = []
  try {
    const resp = await listDocuments({})
    const docs = Array.isArray((resp as any)?.items)
      ? ((resp as any).items as Array<{
          id: string
          title: string
          type: string
          path?: string
          updated_at?: string
        }>)
      : []
    items = docs.map((d) => ({
      id: d.id,
      title: d.title,
      document_type: d.type,
      path: (d as any).path,
      updated_at: (d as any).updated_at,
    }))
  } catch {}

  // Deduplicate
  const seen = new Set<string>()
  const uniq: SearchResult[] = []
  for (const it of items) {
    if (it && it.id && !seen.has(it.id)) {
      seen.add(it.id)
      uniq.push(it)
    }
  }

  // Track duplicates by title
  const titleCounts = new Map<string, number>()
  for (const it of uniq) {
    const t = (it.title || '').toLowerCase()
    if (!t) continue
    titleCounts.set(t, (titleCounts.get(t) || 0) + 1)
  }
  const duplicates = new Set<string>()
  titleCounts.forEach((c, t) => {
    if (c > 1) duplicates.add(t)
  })

  // Build completions
  const options: Completion[] = []

  // Add "Create new" option if query is not empty
  if (query && query.length > 0) {
    options.push({
      label: `Create "${query}"`,
      detail: 'Create a new document',
      info: 'Create a new document with this title (link will use document ID)',
      apply: (view: EditorView, _completion: Completion, _from: number, _to: number) => {
        const insertText = hasClosing ? query : `${query}]]`
        view.dispatch({
          changes: { from: match.from + prefix.length, to: context.pos, insert: insertText },
          selection: { anchor: match.from + prefix.length + insertText.length },
        })
      },
      boost: 99,
    })
  }

  // Add document completions
  for (const doc of uniq) {
    const isDup = duplicates.has((doc.title || '').toLowerCase())
    const typeLower = (doc.document_type || '').toLowerCase()
    const typeDisplay =
      typeLower === 'folder' ? 'Folder' : typeLower === 'scrap' ? 'Scrap' : 'Document'

    options.push({
      label: doc.title || 'Untitled',
      detail: isDup ? doc.path || '' : typeDisplay,
      info: () => {
        const el = document.createElement('div')
        el.innerHTML = `<strong>${doc.title || 'Untitled'}</strong><br/>${
          isDup ? `Path: ${doc.path || ''}<br/>` : ''
        }Type: ${typeDisplay}<br/>ID: ${doc.id}${doc.updated_at ? `<br/>Updated: ${doc.updated_at}` : ''}`
        el.style.cssText = 'font-size: 12px; line-height: 1.5;'
        return el
      },
      apply: (view: EditorView, _completion: Completion, _from: number, _to: number) => {
        const insertText = hasClosing ? doc.id : `${doc.id}]]`
        view.dispatch({
          changes: { from: match.from + prefix.length, to: context.pos, insert: insertText },
          selection: { anchor: match.from + prefix.length + insertText.length + (hasClosing ? 2 : 0) },
        })
      },
    })
  }

  return {
    from: match.from + prefix.length,
    options,
    validFor: /^[^\]]*$/,
  }
}

export function wikiLinkExtension(): Extension {
  return autocompletion({
    override: [wikiLinkCompletionSource],
    activateOnTyping: true,
    closeOnBlur: true,
  })
}
