import { useCallback, useEffect, useRef, useState } from 'react'

import { createYjsConnection, destroyYjsConnection } from '@/shared/lib/yjsConnection'
import type { YjsConnection } from '@/shared/lib/yjsConnection'

import { fetchDocumentMeta } from '@/entities/document'

import {
  resolvePluginForDocument,
  type DocumentPluginMatch,
} from '@/features/plugins'

export type SecondaryViewerItemType = 'document' | 'scrap' | 'plugin'

type YTextBinding = {
  ytext: any
  observer: (() => void) | null
}

export function useSecondaryViewerContent(documentId: string | null, documentType: SecondaryViewerItemType) {
  const [content, setContent] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [currentType, setCurrentType] = useState<SecondaryViewerItemType>(documentType)
  const [isInitialLoading, setIsInitialLoading] = useState(false)
  const [pluginMatch, setPluginMatch] = useState<DocumentPluginMatch | null>(null)

  const connectionRef = useRef<YjsConnection | null>(null)
  const ytextRef = useRef<YTextBinding | null>(null)

const cleanupConnection = useCallback(() => {
  const binding = ytextRef.current
  if (binding?.observer) {
    try {
      binding.ytext.unobserve(binding.observer)
    } catch {
      /* noop */
    }
  }
  ytextRef.current = null
  if (connectionRef.current) {
    destroyYjsConnection(connectionRef.current)
    connectionRef.current = null
  }
}, [])

  useEffect(() => {
    let disposed = false
    let statusHandler: ((e: any) => void) | null = null

    const shareToken = (() => {
      try {
        return new URLSearchParams(window.location.search).get('token') || null
      } catch {
        return null
      }
    })()

    setPluginMatch(null)
    setError(null)
    setContent('')
    setCurrentType(documentType)
    setIsInitialLoading(true)
    cleanupConnection()

    if (!documentId) {
      setIsInitialLoading(false)
      return () => {}
    }

    ;(async () => {
      try {
        const plugin = await resolvePluginForDocument(documentId, shareToken, { source: 'secondary' })
        if (disposed) return
        if (plugin) {
          setPluginMatch(plugin)
          setCurrentType('plugin')
          setIsInitialLoading(false)
          return
        }

        if (documentType === 'scrap') {
          setCurrentType('scrap')
          setContent('# Scrap preview is not supported yet.')
          setIsInitialLoading(false)
          return
        }

        try {
          await fetchDocumentMeta(documentId, shareToken ?? undefined)
        } catch {
          /* ignore meta fetch failure */
        }

        const connection = await createYjsConnection(documentId, { token: shareToken ?? undefined })
        if (disposed) {
          destroyYjsConnection(connection)
          return
        }

        connectionRef.current = connection
        const { doc, provider } = connection
        const ytext = doc.getText('content')

        const apply = () => setContent(String(ytext.toString() || ''))
        apply()

        const observer = () => apply()
        ytext.observe(observer)
        ytextRef.current = { ytext, observer }

        statusHandler = (e: any) => {
          if (e?.status === 'connected') apply()
        }
        try {
          provider.on?.('status', statusHandler)
        } catch {
          statusHandler = null
        }

        setCurrentType('document')
      } catch (err: any) {
        if (!disposed) {
          console.error('[plugins] secondary viewer content load failed', documentId, err)
          setError(err?.message || 'Failed to load content')
        }
      } finally {
        if (!disposed) {
          setIsInitialLoading(false)
        }
      }
    })()

    return () => {
      disposed = true
      if (statusHandler && connectionRef.current) {
        try {
          connectionRef.current.provider.off?.('status', statusHandler)
        } catch {
          /* noop */
        }
      }
      cleanupConnection()
    }
  }, [cleanupConnection, documentId, documentType])

  return {
    content,
    error,
    currentType,
    isInitialLoading,
    pluginMatch,
    setError,
  }
}
