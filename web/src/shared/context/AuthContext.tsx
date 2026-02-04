import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import type { IdentityKeyPair, DeviceKeyPair } from '@/shared/lib/crypto'
import { setPopCredentials, clearPopCredentials } from '@/shared/lib/pop-store'

export interface AuthState {
  userId: string
  email: string
  expiresAt: Date
  /** UMK - may be null for device_required state (new device pending approval) */
  umk: Uint8Array | null
  /** Identity keys - may be null for device_required state (new device pending approval) */
  identityKeys: IdentityKeyPair | null
}

export interface DeviceState {
  deviceId: string
  deviceKeys: DeviceKeyPair
}

interface AuthContextValue {
  auth: AuthState | null
  device: DeviceState | null
  isAuthenticated: boolean
  setAuthState: (state: AuthState) => void
  setDeviceState: (state: DeviceState) => void
  clearAuthState: () => void
  currentWorkspaceId: string | null
  setCurrentWorkspaceId: (id: string | null) => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState | null>(null)
  const [device, setDevice] = useState<DeviceState | null>(null)
  const [currentWorkspaceId, setCurrentWorkspaceIdState] = useState<string | null>(null)

  // Sync device state to pop-store for API client access
  useEffect(() => {
    if (device) {
      setPopCredentials(device.deviceId, device.deviceKeys.signingPrivateKey)
    } else {
      clearPopCredentials()
    }
  }, [device])

  const setAuthState = useCallback((state: AuthState) => {
    setAuth(state)
  }, [])

  const setDeviceState = useCallback((state: DeviceState) => {
    setDevice(state)
  }, [])

  const clearAuthState = useCallback(() => {
    setAuth(null)
    setDevice(null)
    clearPopCredentials()
    setCurrentWorkspaceIdState(null)
  }, [])

  const setCurrentWorkspaceId = useCallback((id: string | null) => {
    setCurrentWorkspaceIdState(id)
  }, [])

  // isAuthenticated is true only when user has full auth state (with UMK and identity keys)
  // Partial auth (device_required) should not be considered authenticated for app access
  const isAuthenticated = auth !== null && auth.umk !== null && auth.identityKeys !== null

  const value: AuthContextValue = {
    auth,
    device,
    isAuthenticated,
    setAuthState,
    setDeviceState,
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
