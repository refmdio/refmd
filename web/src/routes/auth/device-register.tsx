/**
 * Device Registration Page
 *
 * Used when a user logs in on a new device that needs to be registered
 * to receive the UMK (User Master Key) from an existing device.
 * Uses SSE for real-time approval notifications.
 */

import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useState, useEffect, useRef, useCallback } from 'react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { useDevice } from '@/features/device'
import { SasVerification } from '@/features/device/ui/SasVerification'
import { useAuthContext } from '@/shared/context/AuthContext'
import {
  generateDsk,
  storeDsk,
  wrapAndStoreDeviceKeys,
  wrapAndStoreUmk,
  storeSessionUmk,
  storeDeviceId,
  decryptUmkFromDevice,
  decryptIdentityPrivateKeys,
  base64UrlDecode,
} from '@/shared/lib/crypto'
import { setPopCredentials } from '@/shared/lib/pop-store'
import { deviceApi, authApi } from '@/shared/api'
import { detectDeviceType, detectDeviceName } from '@/shared/lib/device'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001'

interface DeviceEvent {
  type: 'pending_created' | 'pending_approved' | 'pending_removed'
  pending_id: string
  user_id: string
  device_id?: string
}

export const Route = createFileRoute('/auth/device-register')({
  component: DeviceRegisterPage,
})

function DeviceRegisterPage() {
  const navigate = useNavigate()
  const { auth, setAuthState, setDeviceState } = useAuthContext()
  const { state, startRegistration, reset } = useDevice()

  const [sasEmojis, setSasEmojis] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const hasStartedRef = useRef(false)

  // Refs to avoid stale closures in SSE event handler
  const stateRef = useRef(state)
  const authRef = useRef(auth)
  stateRef.current = state
  authRef.current = auth

  // Auto-detected device info
  const deviceName = detectDeviceName()
  const deviceType = detectDeviceType()

  // Use SAS emojis from state (calculated client-side during registration)
  useEffect(() => {
    if (state.step === 'waiting-for-approval' && state.sasEmojis && !sasEmojis) {
      setSasEmojis(state.sasEmojis)
    }
  }, [state.step, state.sasEmojis, sasEmojis])

  // Auto-start registration
  const handleStartRegistration = useCallback(async () => {
    if (hasStartedRef.current || loading) return
    hasStartedRef.current = true
    setError(null)
    setLoading(true)

    try {
      await startRegistration(deviceName, deviceType)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start registration')
      hasStartedRef.current = false
    } finally {
      setLoading(false)
    }
  }, [deviceName, deviceType, startRegistration, loading])

  // Start registration automatically on mount
  useEffect(() => {
    if (state.step === 'idle' && !hasStartedRef.current) {
      handleStartRegistration()
    }
  }, [state.step, handleStartRegistration])

  // Handle approval - fetch UMK, store keys, and show completion
  // Uses refs to avoid stale closure issues in SSE event handler
  const handleApproval = useCallback(async (deviceId: string) => {
    const currentState = stateRef.current
    const currentAuth = authRef.current

    if (!currentState.deviceKeyPair || !currentAuth) {
      setError('Missing device keys or auth state')
      return
    }

    try {
      // Step 1: Set PoP credentials FIRST (synchronously) so API calls work
      setPopCredentials(deviceId, currentState.deviceKeyPair.signingPrivateKey)

      // Step 2: Generate and store DSK
      const dsk = await generateDsk()
      await storeDsk(dsk)

      // Step 3: Store device keys
      await wrapAndStoreDeviceKeys(currentState.deviceKeyPair, dsk, currentAuth.userId)
      await storeDeviceId(deviceId)

      // Step 4: Fetch the encrypted UMK from the server
      const umkData = await deviceApi.getDeviceUmk(deviceId)

      // Step 5: Decrypt UMK using ECDH
      const senderEcdhPublicKey = base64UrlDecode(umkData.sender_ecdh_public_key)
      const encryptedUmk = base64UrlDecode(umkData.encrypted_umk)
      const nonce = base64UrlDecode(umkData.nonce)

      const umk = decryptUmkFromDevice(
        encryptedUmk,
        nonce,
        currentState.deviceKeyPair.ecdhPrivateKey,
        senderEcdhPublicKey,
        currentAuth.userId,
        umkData.sender_device_id,
        deviceId
      )

      // Step 6: Store UMK locally
      // - IndexedDB (wrapped with DSK) for persistent storage
      // - sessionStorage for immediate use before page reload
      await wrapAndStoreUmk(umk, dsk, currentAuth.userId)
      storeSessionUmk(umk, currentAuth.userId)

      // Step 7: Fetch encrypted identity keys from server and decrypt with UMK
      const meResponse = await authApi.me()
      const identityKeys = decryptIdentityPrivateKeys(
        {
          encryptedEcdhPrivate: base64UrlDecode(meResponse.encrypted_ecdh_private),
          ecdhPrivateNonce: base64UrlDecode(meResponse.encrypted_ecdh_private_nonce),
          encryptedSigningPrivate: base64UrlDecode(meResponse.encrypted_signing_private),
          signingPrivateNonce: base64UrlDecode(meResponse.encrypted_signing_private_nonce),
        },
        umk,
        currentAuth.userId
      )

      // Step 8: Set full auth state with UMK and identity keys
      setAuthState({
        userId: currentAuth.userId,
        email: currentAuth.email,
        expiresAt: currentAuth.expiresAt,
        umk,
        identityKeys,
      })

      // Step 9: Set device state in context for PoP authentication
      setDeviceState({
        deviceId,
        deviceKeys: currentState.deviceKeyPair,
      })

      // Step 10: Navigate to dashboard
      navigate({ to: '/' })
    } catch (err) {
      console.error('Failed to complete device approval:', err)
      setError(err instanceof Error ? err.message : 'Failed to complete device setup')
    }
  }, [navigate, setAuthState, setDeviceState])

  // SSE for approval status with polling fallback
  useEffect(() => {
    if (state.step !== 'waiting-for-approval' || !state.pendingDeviceId) {
      return
    }

    let isHandled = false
    let pollInterval: ReturnType<typeof setInterval> | null = null

    // Connect to SSE endpoint for this pending device
    const eventSource = new EventSource(
      `${API_BASE}/api/devices/pending/${state.pendingDeviceId}/events`,
      { withCredentials: true }
    )
    eventSourceRef.current = eventSource

    eventSource.onmessage = async (event) => {
      if (isHandled) return
      try {
        const data: DeviceEvent = JSON.parse(event.data)

        if (data.type === 'pending_approved' && data.pending_id === state.pendingDeviceId) {
          isHandled = true
          eventSource.close()
          eventSourceRef.current = null
          if (pollInterval) clearInterval(pollInterval)

          if (data.device_id) {
            await handleApproval(data.device_id)
          }
        } else if (data.type === 'pending_removed' && data.pending_id === state.pendingDeviceId) {
          isHandled = true
          eventSource.close()
          eventSourceRef.current = null
          if (pollInterval) clearInterval(pollInterval)
          setError('Registration was rejected or expired. Please try again.')
          reset()
          // Note: hasStartedRef.current stays true to prevent auto-restart
          // User must manually click "Try Again" to retry
        }
      } catch (err) {
        console.error('Failed to parse SSE event:', err)
      }
    }

    eventSource.onerror = (err) => {
      console.error('SSE connection error:', err)
      // EventSource will automatically reconnect, but we also have polling fallback
    }

    // Polling fallback: check every 5 seconds if pending device still exists
    // This handles cases where SSE connection was interrupted
    // Note: We cannot reliably determine if 404 means approved or rejected,
    // so we only use this for rejection detection. Approval is handled via SSE.
    pollInterval = setInterval(async () => {
      if (isHandled || !state.pendingDeviceId) return

      try {
        const res = await fetch(`${API_BASE}/api/devices/pending/${state.pendingDeviceId}/sas`, {
          credentials: 'include',
        })
        if (res.status === 404) {
          // Pending device no longer exists
          // Could be approved (device_id received via SSE) or rejected/expired
          // Since we can't reliably determine which, show a generic message
          // and let user retry if needed (manual click required)
          isHandled = true
          eventSource.close()
          eventSourceRef.current = null
          if (pollInterval) clearInterval(pollInterval)

          setError('Registration status changed. If approved on another device, please refresh. Otherwise, try again.')
          reset()
          // Note: hasStartedRef.current stays true to prevent auto-restart
          // User must manually click "Try Again" to retry
        }
      } catch {
        // Ignore polling errors - SSE or next poll will handle it
      }
    }, 5000)

    return () => {
      eventSource.close()
      eventSourceRef.current = null
      if (pollInterval) clearInterval(pollInterval)
    }
  // Dependencies simplified: using refs for state/auth to avoid stale closures
  // handleApproval now only depends on stable functions (navigate, setDeviceState)
  }, [state.step, state.pendingDeviceId, navigate, reset, handleApproval])

  const handleCancel = async () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }

    // Delete pending device from server so it doesn't show on existing devices
    if (state.pendingDeviceId) {
      try {
        await deviceApi.rejectPendingDevice(state.pendingDeviceId)
      } catch {
        // Ignore errors - device may already be removed
      }
    }

    reset()
    hasStartedRef.current = false
    navigate({ to: '/auth/login' })
  }

  const handleRetry = () => {
    setError(null)
    hasStartedRef.current = false
    reset()
  }

  // Show loading/registering state
  if (state.step === 'idle' || state.step === 'generating-keys' || state.step === 'creating-pending' || loading) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Registering Device</CardTitle>
            <CardDescription>
              Setting up {deviceName}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {error ? (
              <>
                <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                  {error}
                </div>
                <Button className="w-full" onClick={handleRetry}>
                  Try Again
                </Button>
                <Button variant="outline" className="w-full" onClick={handleCancel}>
                  Back to Login
                </Button>
              </>
            ) : (
              <>
                <div className="flex justify-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
                </div>
                <Button variant="outline" className="w-full" onClick={handleCancel}>
                  Cancel
                </Button>
              </>
            )}
          </CardContent>
        </Card>
      </main>
    )
  }

  // Show SAS verification (waiting for approval)
  if (state.step === 'waiting-for-approval') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Waiting for Approval</CardTitle>
            <CardDescription>
              Verify the emojis on your existing device
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {sasEmojis ? (
              <SasVerification emojis={sasEmojis} role="new" />
            ) : (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
              </div>
            )}

            <div className="text-center text-sm text-muted-foreground">
              <p>Open RefMD on your existing device and approve this device.</p>
              <p className="mt-2">The emojis must match exactly.</p>
            </div>

            <Button
              variant="outline"
              className="w-full"
              onClick={handleCancel}
            >
              Cancel
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  // Show approved state
  if (state.step === 'approved') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Device Approved</CardTitle>
            <CardDescription>
              Your device has been registered successfully
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-center py-4">
              <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-900 flex items-center justify-center">
                <svg
                  className="w-8 h-8 text-green-600 dark:text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
            </div>

            <Button asChild className="w-full">
              <Link to="/dashboard">Continue to Dashboard</Link>
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  // Show error state
  if (state.step === 'error') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold text-destructive">Registration Failed</CardTitle>
            <CardDescription>
              An error occurred during device registration
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
              {state.error || 'Unknown error'}
            </div>

            <Button className="w-full" onClick={handleRetry}>
              Try Again
            </Button>

            <Button
              variant="outline"
              className="w-full"
              onClick={handleCancel}
            >
              Back to Login
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  return null
}
