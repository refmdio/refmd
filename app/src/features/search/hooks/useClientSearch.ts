/**
 * Client-side search hook for E2EE documents
 *
 * Replaces server-side search with MiniSearch in a Web Worker.
 * Provides staged indexing: titles first (instant search), then content (background).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { listDocuments, type Document } from '@/entities/document'

import { fetchDecryptedContent } from '../lib/fetch-decrypted-content'
import type { TitleDocument, WorkerRequest, WorkerResponse } from '../workers/search.worker'

// Re-export document hit type for SearchDialog compatibility
export type DocumentHit = Pick<Document, 'id' | 'title' | 'path' | 'type'>

export interface UseClientSearchParams {
  open: boolean
  query: string | null
  tag: string | null
  workspaceId: string | null
}

export type SearchState =
  | { status: 'idle' }
  | { status: 'initializing' }
  | { status: 'titles_ready'; indexed: number; total: number }
  | { status: 'indexing_content'; indexed: number; total: number }
  | { status: 'ready' }
  | { status: 'limited'; documentCount: number }

export interface UseClientSearchResult {
  docs: DocumentHit[]
  loading: boolean
  searchState: SearchState
}

// Max documents to index for content (memory limit)
const MAX_DOCUMENTS_FOR_CONTENT = 1000

// Debounce delay for search (ms)
const SEARCH_DEBOUNCE_MS = 160

export function useClientSearch(params: UseClientSearchParams): UseClientSearchResult {
  const { open, query, tag, workspaceId } = params

  // All documents from API
  const [allDocs, setAllDocs] = useState<DocumentHit[]>([])

  // Search result IDs (null = no search, show all)
  const [searchResultIds, setSearchResultIds] = useState<string[] | null>(null)

  // Loading state
  const [loading, setLoading] = useState(false)

  // Search/index state
  const [searchState, setSearchState] = useState<SearchState>({ status: 'idle' })

  // Worker reference
  const workerRef = useRef<Worker | null>(null)

  // Track content indexing progress
  const contentIndexedCountRef = useRef(0)

  // Debounced query
  const [debouncedQuery, setDebouncedQuery] = useState<string | null>(null)

  // Debounce query changes
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query)
    }, SEARCH_DEBOUNCE_MS)

    return () => clearTimeout(timer)
  }, [query])

  // Initialize worker
  useEffect(() => {
    workerRef.current = new Worker(new URL('../workers/search.worker.ts', import.meta.url), {
      type: 'module',
    })

    workerRef.current.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const { type } = event.data

      switch (type) {
        case 'indexed-titles': {
          const { count } = event.data as { type: 'indexed-titles'; count: number }
          setSearchState({ status: 'titles_ready', indexed: count, total: count })
          break
        }

        case 'indexed-content': {
          contentIndexedCountRef.current++
          // Update state periodically (every 10 documents)
          if (contentIndexedCountRef.current % 10 === 0) {
            setSearchState((prev) => {
              if (prev.status === 'indexing_content') {
                return { ...prev, indexed: contentIndexedCountRef.current }
              }
              return prev
            })
          }
          break
        }

        case 'search-result': {
          const { ids } = event.data as { type: 'search-result'; ids: string[] }
          setSearchResultIds(ids)
          setLoading(false)
          break
        }

        case 'ready': {
          setSearchState({ status: 'ready' })
          break
        }
      }
    }

    return () => {
      workerRef.current?.terminate()
      workerRef.current = null
    }
  }, [])

  // Index content in background using requestIdleCallback
  const indexContentInBackground = useCallback(
    async (docs: DocumentHit[], wsId: string) => {
      const docsToIndex = docs.slice(0, MAX_DOCUMENTS_FOR_CONTENT)

      if (docsToIndex.length < docs.length) {
        setSearchState({ status: 'limited', documentCount: docsToIndex.length })
      } else {
        setSearchState({ status: 'indexing_content', indexed: 0, total: docsToIndex.length })
      }

      contentIndexedCountRef.current = 0

      for (const doc of docsToIndex) {
        // Use requestIdleCallback for non-blocking indexing
        await new Promise<void>((resolve) => {
          if ('requestIdleCallback' in window) {
            requestIdleCallback(() => resolve(), { timeout: 5000 })
          } else {
            setTimeout(resolve, 0)
          }
        })

        try {
          const content = await fetchDecryptedContent(doc.id, wsId)

          workerRef.current?.postMessage({
            type: 'index-content',
            payload: { id: doc.id, content },
          } satisfies WorkerRequest)
        } catch {
          // Skip documents that fail to fetch
        }
      }

      // Mark as ready when done
      if (docsToIndex.length === docs.length) {
        setSearchState({ status: 'ready' })
      }
    },
    []
  )

  // Phase 1: Load documents and index titles when dialog opens
  useEffect(() => {
    if (!open || !workspaceId) {
      setSearchState({ status: 'idle' })
      setSearchResultIds(null)
      setAllDocs([])
      return
    }

    let cancelled = false
    setLoading(true)
    setSearchState({ status: 'initializing' })

    ;(async () => {
      try {
        const res = await listDocuments({ tag })
        if (cancelled) return

        const items = ((res?.items ?? []) as DocumentHit[]).filter((item) => item.type === 'document')
        setAllDocs(items)

        // Clear previous index and add new titles
        workerRef.current?.postMessage({ type: 'clear' } satisfies WorkerRequest)

        // Small delay to ensure clear is processed
        await new Promise((resolve) => setTimeout(resolve, 10))

        // Index titles
        const titleDocs: TitleDocument[] = items.map((d) => ({
          id: d.id,
          title: d.title,
          path: d.path ?? '',
        }))

        workerRef.current?.postMessage({
          type: 'index-titles',
          payload: { documents: titleDocs },
        } satisfies WorkerRequest)

        setLoading(false)

        // Phase 2-3: Index content in background
        indexContentInBackground(items, workspaceId)
      } catch {
        if (!cancelled) {
          setAllDocs([])
          setLoading(false)
          setSearchState({ status: 'ready' })
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [open, tag, workspaceId, indexContentInBackground])

  // Execute search when debounced query changes
  useEffect(() => {
    if (!open) return

    if (!debouncedQuery || debouncedQuery.trim().length === 0) {
      // No query - show all documents
      setSearchResultIds(null)
      return
    }

    setLoading(true)
    workerRef.current?.postMessage({
      type: 'search',
      payload: { query: debouncedQuery },
    } satisfies WorkerRequest)
  }, [open, debouncedQuery])

  // Filter documents based on search results
  const docs = useMemo(() => {
    if (searchResultIds === null) {
      // No search query - return all documents
      return allDocs
    }

    // Filter by search results and maintain order
    const idSet = new Set(searchResultIds)
    const filtered = allDocs.filter((doc) => idSet.has(doc.id))

    // Sort by search result order
    return filtered.sort((a, b) => {
      const aIndex = searchResultIds.indexOf(a.id)
      const bIndex = searchResultIds.indexOf(b.id)
      return aIndex - bIndex
    })
  }, [allDocs, searchResultIds])

  return { docs, loading, searchState }
}
