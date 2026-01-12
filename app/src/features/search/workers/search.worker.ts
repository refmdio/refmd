/**
 * Search Worker - MiniSearch with staged indexing
 */

import MiniSearch from 'minisearch'

import { tokenize } from '../lib/tokenizer'

// Types
export interface TitleDocument {
  id: string
  title: string
  path: string
}

export type WorkerRequest =
  | { type: 'index-titles'; payload: { documents: TitleDocument[] } }
  | { type: 'index-content'; payload: { id: string; content: string } }
  | { type: 'search'; payload: { query: string } }
  | { type: 'clear' }

export type WorkerResponse =
  | { type: 'indexed-titles'; count: number }
  | { type: 'indexed-content'; id: string }
  | { type: 'search-result'; ids: string[] }
  | { type: 'ready' }

// Internal document structure
interface IndexedDocument {
  id: string
  title: string
  path: string
  content: string
}

// Store document metadata for later content updates
const documentMeta = new Map<string, { title: string; path: string }>()

// MiniSearch instance
const index = new MiniSearch<IndexedDocument>({
  fields: ['title', 'content'],
  storeFields: ['title', 'path'],
  tokenize,
  searchOptions: {
    boost: { title: 2 },
    fuzzy: 0.2,
    prefix: true,
  },
})

// Max content length per document (50,000 chars)
const MAX_CONTENT_LENGTH = 50000

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const { type } = event.data

  switch (type) {
    case 'index-titles': {
      const { documents } = event.data.payload as { documents: TitleDocument[] }

      // Phase 1: Index titles only (content is empty string)
      for (const doc of documents) {
        // Store metadata for later content updates
        documentMeta.set(doc.id, { title: doc.title, path: doc.path })

        // Add to index with empty content
        index.add({
          id: doc.id,
          title: doc.title,
          path: doc.path,
          content: '',
        })
      }

      self.postMessage({ type: 'indexed-titles', count: documents.length } satisfies WorkerResponse)
      break
    }

    case 'index-content': {
      const { id, content } = event.data.payload as { id: string; content: string }

      const meta = documentMeta.get(id)
      if (!meta) {
        // Document not found, skip
        self.postMessage({ type: 'indexed-content', id } satisfies WorkerResponse)
        break
      }

      // Remove existing entry and re-add with content
      try {
        index.discard(id)
      } catch {
        // Document might not exist, ignore
      }

      // Truncate content to max length
      const truncatedContent = content.slice(0, MAX_CONTENT_LENGTH)

      index.add({
        id,
        title: meta.title,
        path: meta.path,
        content: truncatedContent,
      })

      self.postMessage({ type: 'indexed-content', id } satisfies WorkerResponse)
      break
    }

    case 'search': {
      const { query } = event.data.payload as { query: string }

      if (!query || query.trim().length === 0) {
        self.postMessage({ type: 'search-result', ids: [] } satisfies WorkerResponse)
        break
      }

      const results = index.search(query)
      const ids = results.slice(0, 100).map((r) => r.id)

      self.postMessage({ type: 'search-result', ids } satisfies WorkerResponse)
      break
    }

    case 'clear': {
      index.removeAll()
      documentMeta.clear()
      self.postMessage({ type: 'ready' } satisfies WorkerResponse)
      break
    }
  }
}
