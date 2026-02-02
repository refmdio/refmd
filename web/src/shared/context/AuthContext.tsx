import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { IdentityKeyPair } from '@/shared/lib/crypto'

export interface AuthState {
  userId: string
  email: string
  expiresAt: Date
  umk: Uint8Array
  identityKeys: IdentityKeyPair
}

interface AuthContextValue {
  auth: AuthState | null
  isAuthenticated: boolean
  setAuthState: (state: AuthState) => void
  clearAuthState: () => void
  currentWorkspaceId: string | null
  setCurrentWorkspaceId: (id: string | null) => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState | null>(null)
  const [currentWorkspaceId, setCurrentWorkspaceIdState] = useState<string | null>(null)

  const setAuthState = useCallback((state: AuthState) => {
    setAuth(state)
  }, [])

  const clearAuthState = useCallback(() => {
    setAuth(null)
    setCurrentWorkspaceIdState(null)
  }, [])

  const setCurrentWorkspaceId = useCallback((id: string | null) => {
    setCurrentWorkspaceIdState(id)
  }, [])

  const value: AuthContextValue = {
    auth,
    isAuthenticated: auth !== null,
    setAuthState,
    clearAuthState,
    currentWorkspaceId,
    setCurrentWorkspaceId,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuthContext must be used within an AuthProvider')
  }
  return context
}
