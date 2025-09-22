import type * as monacoNs from 'monaco-editor'

import { listDocuments } from '@/entities/document'

type SearchResult = {
  id: string
  title: string
  document_type: string
  path?: string | null
  updated_at?: string
}

export function registerWikiLinkCompletion(monaco: typeof monacoNs) {
  const provider: monacoNs.languages.CompletionItemProvider = {
    triggerCharacters: ['[', '!', '@', '|', ' ', '-'],
    async provideCompletionItems(model, position) {
      const before = model.getValueInRange({ startLineNumber: position.lineNumber, startColumn: 1, endLineNumber: position.lineNumber, endColumn: position.column })
      const after = model.getValueInRange({ startLineNumber: position.lineNumber, startColumn: position.column, endLineNumber: position.lineNumber, endColumn: model.getLineMaxColumn(position.lineNumber) })
      const wiki = before.match(/(\[\[)([^\]]*?)$/)
      const embed = before.match(/(!\[\[)([^\]]*?)$/)
      const mention = before.match(/(@\[\[)([^\]]*?)$/)
      const match = wiki || embed || mention
      if (!match) return { suggestions: [] }
      const q = match[2] || ''
      const hasClosing = after.startsWith(']]')
      let items: SearchResult[] = []
      try {
        const resp = await listDocuments({ query: q || null })
        const docs = Array.isArray((resp as any)?.items) ? (resp as any).items as Array<{ id: string; title: string; type: string; path?: string; updated_at?: string }> : []
        items = docs.map(d => ({ id: d.id, title: d.title, document_type: d.type, path: (d as any).path, updated_at: (d as any).updated_at }))
      } catch {}
      const seen = new Set<string>()
      const uniq: SearchResult[] = []
      for (const it of items) { if (it && it.id && !seen.has(it.id)) { seen.add(it.id); uniq.push(it) } }
      const titleCounts = new Map<string, number>()
      for (const it of uniq) { const t = (it.title || '').toLowerCase(); if (!t) continue; titleCounts.set(t, (titleCounts.get(t) || 0) + 1) }
      const duplicates = new Set<string>()
      titleCounts.forEach((c, t) => { if (c > 1) duplicates.add(t) })

      const range: monacoNs.IRange = { startLineNumber: position.lineNumber, startColumn: position.column - q.length, endLineNumber: position.lineNumber, endColumn: position.column }
      const suggestions: monacoNs.languages.CompletionItem[] = uniq.map((doc) => {
        const isDup = duplicates.has((doc.title || '').toLowerCase())
        const insertText = hasClosing ? (doc.id || '') : `${doc.id}]]`
        const typeLower = (doc.document_type || '').toLowerCase()
        const typeDisplay = typeLower === 'folder' ? 'Folder' : typeLower === 'scrap' ? 'Scrap' : 'Document'
        const updated = doc.updated_at || ''
        const path = doc.path || ''
        const documentation = `**${doc.title || 'Untitled'}**\n\n${isDup ? `Path: ${path}\n\n` : ''}Type: ${typeDisplay}\nID: ${doc.id}\n${updated ? `Updated: ${updated}` : ''}`
        return {
          label: doc.title || 'Untitled',
          kind: monaco.languages.CompletionItemKind.File,
          detail: isDup ? (path || '') : typeDisplay,
          documentation: { value: documentation },
          insertText,
          range,
          command: hasClosing
            ? { id: 'cursorMove', title: 'Move cursor', arguments: [{ to: 'right', by: 'character', value: 2 }] }
            : { id: 'editor.action.triggerSuggest', title: 'Re-trigger suggestions' },
        }
      })
      if (q && q.length > 0) {
        suggestions.unshift({
          label: `Create "${q}"`,
          kind: monaco.languages.CompletionItemKind.Constant,
          detail: 'Create a new document',
          documentation: 'Create a new document with this title (link will use document ID)',
          insertText: hasClosing ? q : `${q}]]`,
          range,
        })
      }
      return { suggestions }
    },
  }
  const disp = monaco.languages.registerCompletionItemProvider('markdown', provider)
  return disp
}
