import { createContext, useContext, useState, useCallback, useMemo, type ReactNode } from 'react'

/**
 * ShareContext manages E2EE state for shared folders/documents.
 *
 * This context stores:
 * - shareKey: The decryption key extracted from URL fragment (#key=xxx)
 * - encryptedDeks: Map of documentId to encrypted DEK (base64)
 *
 * This replaces the fragile URL hash-based approach where the share key
 * could be lost during SPA navigation.
 */

export interface ShareContextValue {
  /** The share key extracted from URL fragment, used to decrypt document DEKs */
  shareKey: Uint8Array | null
  /** Parent folder share token */
  parentToken: string | null
  /** Map of documentId → encrypted DEK (base64, nonce prepended) */
  encryptedDeks: Map<string, string>
  /** Set the share key (called once on share route mount) */
  setShareKey: (key: Uint8Array) => void
  /** Set the parent token */
  setParentToken: (token: string) => void
  /** Set all encrypted DEKs at once */
  setEncryptedDeks: (deks: Map<string, string>) => void
  /** Add or update a single encrypted DEK */
  addEncryptedDek: (documentId: string, encryptedDek: string) => void
}

const ShareContext = createContext<ShareContextValue | null>(null)

export interface ShareProviderProps {
  children: ReactNode
}

export function ShareProvider({ children }: ShareProviderProps) {
  const [shareKey, setShareKeyState] = useState<Uint8Array | null>(null)
  const [parentToken, setParentTokenState] = useState<string | null>(null)
  const [encryptedDeks, setEncryptedDeksState] = useState<Map<string, string>>(new Map())

  const setShareKey = useCallback((key: Uint8Array) => {
    setShareKeyState(key)
  }, [])

  const setParentToken = useCallback((token: string) => {
    setParentTokenState(token)
  }, [])

  const setEncryptedDeks = useCallback((deks: Map<string, string>) => {
    setEncryptedDeksState(deks)
  }, [])

  const addEncryptedDek = useCallback((documentId: string, encryptedDek: string) => {
    setEncryptedDeksState((prev) => {
      const next = new Map(prev)
      next.set(documentId, encryptedDek)
      return next
    })
  }, [])

  const value = useMemo<ShareContextValue>(
    () => ({
      shareKey,
      parentToken,
      encryptedDeks,
      setShareKey,
      setParentToken,
      setEncryptedDeks,
      addEncryptedDek,
    }),
    [shareKey, parentToken, encryptedDeks, setShareKey, setParentToken, setEncryptedDeks, addEncryptedDek]
  )

  return <ShareContext.Provider value={value}>{children}</ShareContext.Provider>
}

/**
 * Hook to access share context. Throws if used outside ShareProvider.
 */
export function useShareContext(): ShareContextValue {
  const ctx = useContext(ShareContext)
  if (!ctx) {
    throw new Error('useShareContext must be used within ShareProvider')
  }
  return ctx
}

/**
 * Hook to optionally access share context.
 * Returns null if not within ShareProvider (e.g., in regular document routes).
 * This is useful for hooks that need to support both share and non-share contexts.
 */
export function useShareContextOptional(): ShareContextValue | null {
  return useContext(ShareContext)
}
