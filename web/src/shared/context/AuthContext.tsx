import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import { setPopCredentials, clearPopCredentials } from '@/shared/lib/pop-store'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'
export type { AuthState, DeviceState } from '@/shared/model/auth-types'

interface AuthContextValue {
  auth: AuthState | null
  device: DeviceState | null
  isAuthenticated: boolean
  setAuthState: (state: AuthState) => void
  /** Set both auth and device state atomically (full session establishment). */
  setFullSession: (auth: AuthState, device: DeviceState) => void
  clearAuthState: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState | null>(null)
  const [device, setDevice] = useState<DeviceState | null>(null)

  const setAuthState = useCallback((state: AuthState) => {
    setAuth(state)
    // Clear stale device state and PoP credentials when setting partial auth
    // (e.g. device_required transition) to prevent using credentials from a previous session
    setDevice(null)
    clearPopCredentials()
  }, [])

  const setFullSession = useCallback((authState: AuthState, deviceState: DeviceState) => {
    setAuth(authState)
    setPopCredentials(deviceState.deviceId, deviceState.deviceKeys.signingPrivateKey)
    setDevice(deviceState)
  }, [])

  const clearAuthState = useCallback(() => {
    setAuth(null)
    setDevice(null)
    clearPopCredentials()
  }, [])

  // isAuthenticated is true only when user has full auth state (with UMK and identity keys)
  // Partial auth (device_required) should not be considered authenticated for app access
  const isAuthenticated = auth !== null && auth.umk !== null && auth.identityKeys !== null

  const value: AuthContextValue = {
    auth,
    device,
    isAuthenticated,
    setAuthState,
    setFullSession,
    clearAuthState,
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
