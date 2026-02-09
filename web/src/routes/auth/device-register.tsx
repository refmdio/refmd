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
  verifyTofu,
  handleTofuResult,
  trustDevice,
  decryptTrustState,
  wrapAndStorePdkDeviceKeys,
  wrapAndStorePdkUmk,
  loadAndClearPdkForDeviceRegistration,
} from '@/shared/lib/crypto'
import { importTofuEntries } from '@/shared/lib/trust-store'
import { KeyChangeWarningDialog } from '@/features/tofu'
import { setPopCredentials } from '@/shared/lib/pop-store'
import { deviceApi, authApi, trustTransferApi, sseUrls } from '@/shared/api'
import { detectDeviceType, detectDeviceName } from '@/shared/lib/device'

interface DeviceEvent {
  type: 'pending_created' | 'pending_approved' | 'pending_removed' | 'pending_expired'
  pending_id: string
  user_id: string
  device_id?: string
}

export const Route = createFileRoute('/auth/device-register')({
  component: DeviceRegisterPage,
})

function DeviceRegisterPage() {
  const navigate = useNavigate()
  const { auth, setAuthState, setDeviceState, clearAuthState } = useAuthContext()
  const { state, startRegistration, reset } = useDevice()

  const [sasEmojis, setSasEmojis] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [keyChangeWarning, setKeyChangeWarning] = useState<{
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
    deviceId: string
    senderDeviceId: string
  } | null>(null)
  // Trust Transfer specific key change warning (separate from UMK sender warning)
  const [trustTransferKeyChangeWarning, setTrustTransferKeyChangeWarning] = useState<{
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
    senderDeviceId: string
    senderDeviceName: string
    // Data needed to complete the import after user confirms
    pendingImport: {
      encryptedState: { encryptedState: Uint8Array; nonce: Uint8Array; signature: Uint8Array }
      senderEcdhPk: Uint8Array
      senderSigningPk: Uint8Array
      transferNonce: Uint8Array
      userId: string
      deviceId: string
      deviceKeyPair: { ecdhPrivateKey: Uint8Array }
    }
  } | null>(null)
  // Queue of devices with identity_key_changed during Trust Transfer all-device verification
  const [trustTransferDeviceKeyChangeQueue, setTrustTransferDeviceKeyChangeQueue] = useState<Array<{
    deviceId: string
    deviceName: string
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
  }>>([])
  // Pending Trust Transfer data while processing device key change queue
  const [pendingTrustTransferData, setPendingTrustTransferData] = useState<{
    devices: Array<{ id: string; name: string; signing_public_key: string; ecdh_public_key: string }>
    stateResponse: { sender_device_id: string; ciphertext: string; nonce: string; signature: string }
    transferNonce: Uint8Array
    deviceId: string
    deviceKeyPair: { ecdhPrivateKey: Uint8Array }
    currentAuth: { userId: string }
  } | null>(null)
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

      // Step 4.5: TOFU verification - verify sender device before decrypting UMK
      const senderEcdhPublicKey = base64UrlDecode(umkData.sender_ecdh_public_key)
      const senderSigningPublicKey = base64UrlDecode(umkData.sender_signing_public_key)

      const tofuResult = await verifyTofu(
        currentAuth.userId,
        umkData.sender_device_id,
        senderSigningPublicKey,
        senderEcdhPublicKey
      )

      // Handle TOFU result
      if (tofuResult.status === 'ecdh_key_mismatch') {
        throw new Error('Sender device key mismatch. UMK decryption aborted for security.')
      }

      if (tofuResult.status === 'identity_key_changed') {
        // Show warning dialog for identity key change
        setKeyChangeWarning({
          oldFingerprint: tofuResult.oldFingerprint!,
          newFingerprint: tofuResult.newFingerprint!,
          tofuResult,
          deviceId,
          senderDeviceId: umkData.sender_device_id,
        })
        return // Wait for user confirmation
      }

      // Trust the sender device (handles first_seen and updates last_seen for known_trusted)
      await handleTofuResult(tofuResult)

      // Step 5: Decrypt UMK using ECDH
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

      // Step 6.5: PDK fallback wrapping (if PDK was stored during login)
      const pdk = loadAndClearPdkForDeviceRegistration()
      if (pdk) {
        wrapAndStorePdkDeviceKeys(
          {
            ecdhPrivateKey: currentState.deviceKeyPair.ecdhPrivateKey,
            signingPrivateKey: currentState.deviceKeyPair.signingPrivateKey,
          },
          pdk,
          currentAuth.userId,
          deviceId
        )
        wrapAndStorePdkUmk(umk, pdk, currentAuth.userId)
      }

      // Step 7: Fetch encrypted identity keys from server and decrypt with UMK
      const meResponse = await authApi.me()
      if (!meResponse.keys) {
        throw new Error('Device not verified: no keys returned from server')
      }
      const meKeys = meResponse.keys
      const identityKeys = decryptIdentityPrivateKeys(
        {
          encryptedEcdhPrivate: base64UrlDecode(meKeys.encrypted_ecdh_private),
          ecdhPrivateNonce: base64UrlDecode(meKeys.encrypted_ecdh_private_nonce),
          encryptedSigningPrivate: base64UrlDecode(meKeys.encrypted_signing_private),
          signingPrivateNonce: base64UrlDecode(meKeys.encrypted_signing_private_nonce),
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

      // Step 10: Request trust transfer nonce and retrieve trust state
      // This is non-blocking - we continue even if it fails
      try {
        console.log('[Trust Transfer] Requesting nonce for device:', deviceId)
        const nonceResponse = await trustTransferApi.requestNonce(deviceId)
        if (!nonceResponse) {
          console.warn('[Trust Transfer] No nonce response received')
        } else {
          console.log('[Trust Transfer] Nonce received, waiting for trust state...')

          // Poll for trust state (existing device will submit after receiving the SSE event)
          const transferNonce = base64UrlDecode(nonceResponse.nonce)
          let trustStateReceived = false

          for (let attempt = 0; attempt < 10 && !trustStateReceived; attempt++) {
            try {
              const stateResponse = await trustTransferApi.retrieveState(deviceId)
              if (!stateResponse) {
                await new Promise(r => setTimeout(r, 500))
                continue
              }
              console.log('[Trust Transfer] Trust state received')

              // Decrypt and import trust state
              const encryptedState = {
                encryptedState: base64UrlDecode(stateResponse.ciphertext),
                nonce: base64UrlDecode(stateResponse.nonce),
                signature: base64UrlDecode(stateResponse.signature),
              }

              // Get all devices and verify TOFU for each (design requirement)
              const devices = await deviceApi.listDevices()

              // Collect devices with identity_key_changed for sequential dialog confirmation
              const devicesWithKeyChange: Array<{
                deviceId: string
                deviceName: string
                oldFingerprint: string
                newFingerprint: string
                tofuResult: Awaited<ReturnType<typeof verifyTofu>>
              }> = []

              // Verify all devices per design spec
              for (const device of devices.devices) {
                if (device.signing_public_key && device.ecdh_public_key) {
                  try {
                    const signingPk = base64UrlDecode(device.signing_public_key)
                    const ecdhPk = base64UrlDecode(device.ecdh_public_key)
                    const deviceTofuResult = await verifyTofu(
                      currentAuth.userId,
                      device.id,
                      signingPk,
                      ecdhPk
                    )

                    if (deviceTofuResult.status === 'ecdh_key_mismatch') {
                      console.error('[Trust Transfer] ECDH key mismatch for device:', device.id)
                      setError(`Trust transfer aborted: Device "${device.name}" has a key mismatch. This may indicate a security issue.`)
                      return
                    }

                    if (deviceTofuResult.status === 'identity_key_changed') {
                      // Queue for warning dialog (user confirmation required)
                      devicesWithKeyChange.push({
                        deviceId: device.id,
                        deviceName: device.name,
                        oldFingerprint: deviceTofuResult.oldFingerprint!,
                        newFingerprint: deviceTofuResult.newFingerprint!,
                        tofuResult: deviceTofuResult,
                      })
                      continue
                    }

                    // Handle first_seen and known_trusted automatically
                    if (deviceTofuResult.status === 'first_seen' || deviceTofuResult.status === 'known_trusted') {
                      await handleTofuResult(deviceTofuResult)
                    }
                  } catch (err) {
                    console.error('[Trust Transfer] TOFU verification failed for device:', device.id, err)
                  }
                }
              }

              // If any devices have identity_key_changed, show dialogs before proceeding
              if (devicesWithKeyChange.length > 0) {
                console.log('[Trust Transfer] Devices with key change require confirmation:', devicesWithKeyChange.length)
                setTrustTransferDeviceKeyChangeQueue(devicesWithKeyChange)
                setPendingTrustTransferData({
                  devices: devices.devices.map(d => ({
                    id: d.id,
                    name: d.name,
                    signing_public_key: d.signing_public_key,
                    ecdh_public_key: d.ecdh_public_key,
                  })),
                  stateResponse,
                  transferNonce,
                  deviceId,
                  deviceKeyPair: { ecdhPrivateKey: currentState.deviceKeyPair.ecdhPrivateKey },
                  currentAuth: { userId: currentAuth.userId },
                })
                return // Wait for user to confirm each device
              }

              const senderDevice = devices.devices.find(d => d.id === stateResponse.sender_device_id)
              if (!senderDevice) {
                console.warn('[Trust Transfer] Sender device not found, skipping import')
                break
              }

              const senderEcdhPk = base64UrlDecode(senderDevice.ecdh_public_key)
              const senderSigningPk = base64UrlDecode(senderDevice.signing_public_key)

              // TOFU verification for sender device (specifically for import decision)
              const senderTofuResult = await verifyTofu(
                currentAuth.userId,
                stateResponse.sender_device_id,
                senderSigningPk,
                senderEcdhPk
              )

              if (senderTofuResult.status === 'ecdh_key_mismatch') {
                console.error('[Trust Transfer] Sender ECDH key mismatch detected')
                setError('Trust transfer aborted: Sender device key mismatch detected. This may indicate a security issue.')
                return
              }

              if (senderTofuResult.status === 'identity_key_changed') {
                // Show warning dialog and wait for user confirmation
                console.warn('[Trust Transfer] Sender identity key changed, requesting user confirmation')
                setTrustTransferKeyChangeWarning({
                  oldFingerprint: senderTofuResult.oldFingerprint!,
                  newFingerprint: senderTofuResult.newFingerprint!,
                  tofuResult: senderTofuResult,
                  senderDeviceId: stateResponse.sender_device_id,
                  senderDeviceName: senderDevice.name,
                  pendingImport: {
                    encryptedState,
                    senderEcdhPk,
                    senderSigningPk,
                    transferNonce,
                    userId: currentAuth.userId,
                    deviceId,
                    deviceKeyPair: { ecdhPrivateKey: currentState.deviceKeyPair.ecdhPrivateKey },
                  },
                })
                // Don't navigate yet - dialog will be shown and handle the rest
                return
              } else {
                await handleTofuResult(senderTofuResult)
              }

              const snapshot = decryptTrustState(
                encryptedState,
                currentState.deviceKeyPair.ecdhPrivateKey,
                senderEcdhPk,
                senderSigningPk,
                transferNonce,
                {
                  userId: currentAuth.userId,
                  senderDeviceId: stateResponse.sender_device_id,
                  targetDeviceId: deviceId,
                }
              )

              // Import TOFU entries
              await importTofuEntries(snapshot.tofuEntries)
              console.log('[Trust Transfer] Imported', snapshot.tofuEntries.length, 'TOFU entries')
              trustStateReceived = true
            } catch (err) {
              // 404 means trust state not yet available
              if (err && typeof err === 'object' && 'status' in err && err.status === 404) {
                await new Promise(r => setTimeout(r, 500))
                continue
              }
              console.warn('[Trust Transfer] Error retrieving trust state:', err)
              break
            }
          }

          if (!trustStateReceived) {
            console.log('[Trust Transfer] Timed out waiting for trust state, continuing without it')
          }
        }
      } catch (err) {
        console.warn('[Trust Transfer] Failed to request nonce:', err)
        // Continue without trust transfer - not blocking
      }

      // Step 11: Navigate to dashboard
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
      sseUrls.pendingDeviceEvents(state.pendingDeviceId),
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
          setError('Registration was rejected. Please try again.')
          reset()
          // Note: hasStartedRef.current stays true to prevent auto-restart
          // User must manually click "Try Again" to retry
        } else if (data.type === 'pending_expired' && data.pending_id === state.pendingDeviceId) {
          isHandled = true
          eventSource.close()
          eventSourceRef.current = null
          if (pollInterval) clearInterval(pollInterval)
          setError('Registration expired. Please try again.')
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
        await deviceApi.getSas(state.pendingDeviceId)
      } catch (err) {
        // Check if pending device no longer exists (404) or expired (410)
        if (err && typeof err === 'object' && 'status' in err) {
          const status = (err as { status: number }).status
          if (status === 410) {
            // Pending device expired (410 Gone)
            isHandled = true
            eventSource.close()
            eventSourceRef.current = null
            if (pollInterval) clearInterval(pollInterval)

            setError('Registration expired. Please try again.')
            reset()
            // Note: hasStartedRef.current stays true to prevent auto-restart
            // User must manually click "Try Again" to retry
          } else if (status === 404) {
            // Pending device no longer exists - could be approved or rejected.
            // SSE may be delivering the approval event concurrently, so wait
            // briefly before showing an error to avoid a race condition.
            await new Promise(r => setTimeout(r, 2000))
            if (isHandled) return // SSE caught up during the grace period

            isHandled = true
            eventSource.close()
            eventSourceRef.current = null
            if (pollInterval) clearInterval(pollInterval)

            setError('Registration status changed. If approved on another device, please refresh. Otherwise, try again.')
            reset()
            // Note: hasStartedRef.current stays true to prevent auto-restart
            // User must manually click "Try Again" to retry
          }
        }
        // Ignore other polling errors - SSE or next poll will handle it
      }
    }, 5000)

    return () => {
      isHandled = true // prevent delayed polling callbacks after unmount
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

    // Logout to clear session cookie and auth state
    try {
      await authApi.logout()
    } catch {
      // Ignore logout errors
    }

    // Clear client-side auth state
    clearAuthState()
    reset()
    hasStartedRef.current = false
    navigate({ to: '/auth/login' })
  }

  const handleRetry = () => {
    setError(null)
    hasStartedRef.current = false
    reset()
  }

  // Key change warning handlers
  const handleKeyChangeTrust = async () => {
    if (!keyChangeWarning) return

    // Trust the new key by saving the new entry
    await trustDevice(keyChangeWarning.tofuResult.newEntry)
    setKeyChangeWarning(null)

    // Resume the approval process
    await handleApproval(keyChangeWarning.deviceId)
  }

  const handleKeyChangeBlock = async () => {
    // Block - just cancel the registration
    setKeyChangeWarning(null)
    setError('Device approval cancelled due to key change concerns.')
  }

  const handleKeyChangeCancel = () => {
    setKeyChangeWarning(null)
    setError('Device approval paused. Verify the sender device before continuing.')
  }

  // Trust Transfer key change warning handlers
  const handleTrustTransferKeyChangeTrust = async () => {
    if (!trustTransferKeyChangeWarning) return

    const { tofuResult, pendingImport } = trustTransferKeyChangeWarning

    // Trust the new key by saving the new entry
    await trustDevice(tofuResult.newEntry)

    // Complete the import
    try {
      const snapshot = decryptTrustState(
        pendingImport.encryptedState,
        pendingImport.deviceKeyPair.ecdhPrivateKey,
        pendingImport.senderEcdhPk,
        pendingImport.senderSigningPk,
        pendingImport.transferNonce,
        {
          userId: pendingImport.userId,
          senderDeviceId: trustTransferKeyChangeWarning.senderDeviceId,
          targetDeviceId: pendingImport.deviceId,
        }
      )

      await importTofuEntries(snapshot.tofuEntries)
      console.log('[Trust Transfer] Imported', snapshot.tofuEntries.length, 'TOFU entries after user confirmation')
    } catch (err) {
      console.error('[Trust Transfer] Failed to import after confirmation:', err)
    }

    setTrustTransferKeyChangeWarning(null)
    navigate({ to: '/' })
  }

  const handleTrustTransferKeyChangeBlock = () => {
    // Skip trust transfer import and continue to dashboard
    console.log('[Trust Transfer] User blocked trust transfer due to key change')
    setTrustTransferKeyChangeWarning(null)
    navigate({ to: '/' })
  }

  const handleTrustTransferKeyChangeCancel = () => {
    // Same as block - skip import and continue
    console.log('[Trust Transfer] User cancelled trust transfer dialog')
    setTrustTransferKeyChangeWarning(null)
    navigate({ to: '/' })
  }

  // Trust Transfer device key change queue handlers (for non-sender devices)
  const currentDeviceKeyChange = trustTransferDeviceKeyChangeQueue[0]

  const continueTrustTransferAfterKeyChanges = async () => {
    if (!pendingTrustTransferData) return

    const { devices, stateResponse, transferNonce, deviceId, deviceKeyPair, currentAuth } = pendingTrustTransferData

    // Find sender device
    const senderDevice = devices.find(d => d.id === stateResponse.sender_device_id)
    if (!senderDevice) {
      console.warn('[Trust Transfer] Sender device not found after key change confirmations')
      setPendingTrustTransferData(null)
      navigate({ to: '/' })
      return
    }

    const senderEcdhPk = base64UrlDecode(senderDevice.ecdh_public_key)
    const senderSigningPk = base64UrlDecode(senderDevice.signing_public_key)

    // TOFU verification for sender device
    const senderTofuResult = await verifyTofu(
      currentAuth.userId,
      stateResponse.sender_device_id,
      senderSigningPk,
      senderEcdhPk
    )

    if (senderTofuResult.status === 'ecdh_key_mismatch') {
      console.error('[Trust Transfer] Sender ECDH key mismatch detected')
      setError('Trust transfer aborted: Sender device key mismatch detected.')
      setPendingTrustTransferData(null)
      return
    }

    if (senderTofuResult.status === 'identity_key_changed') {
      // Show sender-specific warning dialog
      setTrustTransferKeyChangeWarning({
        oldFingerprint: senderTofuResult.oldFingerprint!,
        newFingerprint: senderTofuResult.newFingerprint!,
        tofuResult: senderTofuResult,
        senderDeviceId: stateResponse.sender_device_id,
        senderDeviceName: senderDevice.name,
        pendingImport: {
          encryptedState: {
            encryptedState: base64UrlDecode(stateResponse.ciphertext),
            nonce: base64UrlDecode(stateResponse.nonce),
            signature: base64UrlDecode(stateResponse.signature),
          },
          senderEcdhPk,
          senderSigningPk,
          transferNonce,
          userId: currentAuth.userId,
          deviceId,
          deviceKeyPair,
        },
      })
      setPendingTrustTransferData(null)
      return
    }

    await handleTofuResult(senderTofuResult)

    // Complete trust transfer
    try {
      const encryptedState = {
        encryptedState: base64UrlDecode(stateResponse.ciphertext),
        nonce: base64UrlDecode(stateResponse.nonce),
        signature: base64UrlDecode(stateResponse.signature),
      }

      const snapshot = decryptTrustState(
        encryptedState,
        deviceKeyPair.ecdhPrivateKey,
        senderEcdhPk,
        senderSigningPk,
        transferNonce,
        {
          userId: currentAuth.userId,
          senderDeviceId: stateResponse.sender_device_id,
          targetDeviceId: deviceId,
        }
      )

      await importTofuEntries(snapshot.tofuEntries)
      console.log('[Trust Transfer] Imported', snapshot.tofuEntries.length, 'TOFU entries after key change confirmations')
    } catch (err) {
      console.error('[Trust Transfer] Failed to import after key change confirmations:', err)
    }

    setPendingTrustTransferData(null)
    navigate({ to: '/' })
  }

  const handleDeviceKeyChangeTrust = async () => {
    if (!currentDeviceKeyChange) return

    // Trust the new key
    await trustDevice(currentDeviceKeyChange.tofuResult.newEntry)

    // Remove from queue
    const newQueue = trustTransferDeviceKeyChangeQueue.slice(1)
    setTrustTransferDeviceKeyChangeQueue(newQueue)

    // If queue is empty, continue trust transfer
    if (newQueue.length === 0) {
      await continueTrustTransferAfterKeyChanges()
    }
  }

  const handleDeviceKeyChangeBlock = () => {
    // User blocked this device - abort trust transfer
    console.log('[Trust Transfer] User blocked device:', currentDeviceKeyChange?.deviceId)
    setTrustTransferDeviceKeyChangeQueue([])
    setPendingTrustTransferData(null)
    navigate({ to: '/' })
  }

  const handleDeviceKeyChangeCancel = () => {
    // Skip all remaining - abort trust transfer
    console.log('[Trust Transfer] User cancelled device key change dialog')
    setTrustTransferDeviceKeyChangeQueue([])
    setPendingTrustTransferData(null)
    navigate({ to: '/' })
  }

  // Show Trust Transfer device key change dialog (for non-sender devices)
  if (currentDeviceKeyChange) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <KeyChangeWarningDialog
          open={true}
          deviceName={currentDeviceKeyChange.deviceName}
          oldFingerprint={currentDeviceKeyChange.oldFingerprint}
          newFingerprint={currentDeviceKeyChange.newFingerprint}
          onTrust={handleDeviceKeyChangeTrust}
          onBlock={handleDeviceKeyChangeBlock}
          onCancel={handleDeviceKeyChangeCancel}
        />
      </main>
    )
  }

  // Show Trust Transfer key change warning dialog if needed
  if (trustTransferKeyChangeWarning) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <KeyChangeWarningDialog
          open={true}
          deviceName={trustTransferKeyChangeWarning.senderDeviceName}
          oldFingerprint={trustTransferKeyChangeWarning.oldFingerprint}
          newFingerprint={trustTransferKeyChangeWarning.newFingerprint}
          onTrust={handleTrustTransferKeyChangeTrust}
          onBlock={handleTrustTransferKeyChangeBlock}
          onCancel={handleTrustTransferKeyChangeCancel}
        />
      </main>
    )
  }

  // Show key change warning dialog if needed (UMK sender)
  if (keyChangeWarning) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <KeyChangeWarningDialog
          open={true}
          deviceName={`Device ${keyChangeWarning.senderDeviceId.slice(0, 8)}...`}
          oldFingerprint={keyChangeWarning.oldFingerprint}
          newFingerprint={keyChangeWarning.newFingerprint}
          onTrust={handleKeyChangeTrust}
          onBlock={handleKeyChangeBlock}
          onCancel={handleKeyChangeCancel}
        />
      </main>
    )
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
            <CardTitle className="text-2xl font-bold">
              {error ? 'Registration Failed' : 'Waiting for Approval'}
            </CardTitle>
            <CardDescription>
              {error ? 'A security issue was detected' : 'Verify the emojis on your existing device'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
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
              </>
            )}
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
