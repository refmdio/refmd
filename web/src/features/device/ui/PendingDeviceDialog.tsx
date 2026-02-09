/**
 * Pending Device Approval Dialog
 *
 * Automatically shown when a new device registration request is detected.
 * Allows existing device to approve via SAS verification.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { Button } from '@/shared/ui/button'
import { SasVerification } from './SasVerification'
import { deviceApi, workspaceApi, encryptionApi, trustTransferApi, ApiError, sseUrls } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateSasEmojis,
  sign,
  encryptUmkForDevice,
  decryptKekFromDevice,
  encryptKekForDevice,
  verifyTofu,
  handleTofuResult,
  trustDevice,
  buildSignatureMessage,
  SIGNATURE_ACTION,
  encryptTrustState,
} from '@/shared/lib/crypto'
import { getAllTofuEntriesForUser } from '@/shared/lib/trust-store'
import { checkKeyVersionRollback, pinKeyVersion, getKeyVersionPin } from '@/shared/lib/anti-rollback'
import { KeyChangeWarningDialog } from '@/features/tofu'

interface PendingDevice {
  id: string
  name: string
  device_type: string
  ip_address?: string | null
  created_at: string
  expires_at: string
}

interface PendingDeviceDialogProps {
  /** Pending device to approve */
  device: PendingDevice
  /** Called when dialog should close */
  onClose: () => void
  /** Called after successful approval */
  onApproved: () => void
}

export function PendingDeviceDialog({ device, onClose, onApproved }: PendingDeviceDialogProps) {
  const { auth, device: currentDevice } = useAuthContext()
  const [step, setStep] = useState<'loading' | 'verify' | 'approving' | 'error'>('loading')
  const [sasEmojis, setSasEmojis] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pendingDeviceKeys, setPendingDeviceKeys] = useState<{
    signingPk: Uint8Array
    ecdhPk: Uint8Array
    clientNonce: Uint8Array
  } | null>(null)
  const [keyChangeWarning, setKeyChangeWarning] = useState<{
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
  } | null>(null)
  // Track if user has approved a key change (trust will be persisted after approve success)
  const [pendingKeyChangeTrust, setPendingKeyChangeTrust] = useState<Awaited<ReturnType<typeof verifyTofu>> | null>(null)
  const cancelledRef = useRef(false)

  // Load SAS function (reusable for retry)
  const loadSas = useCallback(async () => {
    if (!auth?.identityKeys || !auth?.userId) {
      setError('Identity keys not available')
      setStep('error')
      return
    }

    try {
      setStep('loading')
      setError(null)

      // Get SAS data from server
      const sasResponse = await deviceApi.getSas(device.id)

      // Check if cancelled after async operation
      if (cancelledRef.current) return

      // Decode keys
      const deviceSigningPk = base64UrlDecode(sasResponse.device_signing_public_key)
      const deviceEcdhPk = base64UrlDecode(sasResponse.device_ecdh_public_key)
      const clientNonce = base64UrlDecode(sasResponse.client_nonce)

      // TOFU verification: Check if we've seen this device before
      // For new devices (first_seen), auto-trust after SAS verification
      // For known devices with changed keys, this is an error (should not happen for pending devices)
      const tofuResult = await verifyTofu(
        auth.userId,
        device.id,
        deviceSigningPk,
        deviceEcdhPk
      )

      if (tofuResult.status === 'ecdh_key_mismatch') {
        setError('Device key mismatch detected. Registration aborted for security.')
        setStep('error')
        return
      }

      // Store keys for approval (needed before showing warning dialog)
      const keys = {
        signingPk: deviceSigningPk,
        ecdhPk: deviceEcdhPk,
        clientNonce: clientNonce,
      }
      setPendingDeviceKeys(keys)

      if (tofuResult.status === 'identity_key_changed') {
        // Show warning dialog for identity key change
        setKeyChangeWarning({
          oldFingerprint: tofuResult.oldFingerprint!,
          newFingerprint: tofuResult.newFingerprint!,
          tofuResult,
        })
        return // Wait for user confirmation
      }

      // For first_seen, proceed with SAS verification
      // The actual trust will be established after user confirms SAS emojis

      // Calculate SAS locally
      const emojis = generateSasEmojis(
        auth.identityKeys.signingPublic,
        deviceSigningPk,
        deviceEcdhPk,
        clientNonce
      )
      setSasEmojis(emojis)
      setStep('verify')
    } catch (err) {
      if (cancelledRef.current) return
      setError(err instanceof Error ? err.message : 'Failed to load SAS')
      setStep('error')
    }
  }, [device.id, auth?.identityKeys, auth?.userId])

  // Load SAS on mount with cancellation support
  useEffect(() => {
    cancelledRef.current = false
    loadSas()

    return () => {
      cancelledRef.current = true
    }
  }, [loadSas])

  const handleApprove = async () => {
    if (!auth?.identityKeys || !auth?.umk || !auth?.userId || !currentDevice || !pendingDeviceKeys) {
      setError('Missing required keys or device info')
      setStep('error')
      return
    }

    try {
      setStep('approving')
      setError(null)

      // TOFU re-verification: Verify keys haven't changed since SAS verification
      const tofuResult = await verifyTofu(
        auth.userId,
        device.id,
        pendingDeviceKeys.signingPk,
        pendingDeviceKeys.ecdhPk
      )

      if (tofuResult.status === 'ecdh_key_mismatch') {
        setError('Device key mismatch detected. Approval aborted for security.')
        setStep('error')
        return
      }

      if (tofuResult.status === 'identity_key_changed' && !pendingKeyChangeTrust) {
        // Show warning dialog only if user hasn't already confirmed the key change
        setKeyChangeWarning({
          oldFingerprint: tofuResult.oldFingerprint!,
          newFingerprint: tofuResult.newFingerprint!,
          tofuResult,
        })
        setStep('verify') // Return to verify step to wait for user decision
        return
      }

      // Build signature message using signature protocol format
      const signatureMessage = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_APPROVAL, {
        device_signing_public_key: base64UrlEncode(pendingDeviceKeys.signingPk),
        device_ecdh_public_key: base64UrlEncode(pendingDeviceKeys.ecdhPk),
        client_nonce: base64UrlEncode(pendingDeviceKeys.clientNonce),
      })

      // Sign with identity signing key
      const signature = sign(signatureMessage, auth.identityKeys.signingPrivate)

      // Send approval - returns the new device ID
      const approveResponse = await deviceApi.approveDevice(device.id, {
        identity_signature: base64UrlEncode(signature),
      })

      // Trust the device after successful approval
      // If user approved a key change warning, persist that trust now
      if (pendingKeyChangeTrust) {
        await trustDevice(pendingKeyChangeTrust.newEntry)
        setPendingKeyChangeTrust(null)
      } else {
        // Handle first_seen and known_trusted cases
        await handleTofuResult(tofuResult)
      }

      // Distribute KEKs BEFORE UMK — the distribute_umk endpoint emits the
      // SSE `pending_approved` event that tells the new device to proceed.
      // KEKs must already be on the server so the new device can decrypt
      // workspace keys immediately after receiving the event.
      try {
        console.log('[KEK Distribution] Starting KEK distribution for new device:', approveResponse.id)
        const workspacesResponse = await workspaceApi.list()
        console.log('[KEK Distribution] Workspaces to process:', workspacesResponse.workspaces.length)

        for (const item of workspacesResponse.workspaces) {
          const workspaceId = item.workspace.id
          console.log('[KEK Distribution] Processing workspace:', workspaceId)
          try {
            // Get existing KEK for current device
            const existingKey = await encryptionApi.getWorkspaceKey(workspaceId, currentDevice.deviceId)
            console.log('[KEK Distribution] Got existing KEK for workspace:', workspaceId)

            // Decode the encrypted KEK
            const existingEncryptedKek = base64UrlDecode(existingKey.encrypted_kek)
            const existingNonce = base64UrlDecode(existingKey.nonce)

            // Get sender's ECDH public key (self for current device)
            const senderEcdhPk = existingKey.sender_ecdh_public_key
              ? base64UrlDecode(existingKey.sender_ecdh_public_key)
              : currentDevice.deviceKeys.ecdhPublicKey
            const senderDeviceId = existingKey.sender_device_id || currentDevice.deviceId

            // TOFU verification: verify KEK sender before decryption (fail-close)
            if (senderDeviceId !== currentDevice.deviceId) {
              if (!existingKey.sender_signing_public_key) {
                console.error(`[KEK Distribution] Sender signing key missing for workspace ${workspaceId}, skipping`)
                continue
              }
              const senderSigningPk = base64UrlDecode(existingKey.sender_signing_public_key)
              const kekSenderTofuResult = await verifyTofu(
                auth.userId,
                senderDeviceId,
                senderSigningPk,
                senderEcdhPk
              )

              if (kekSenderTofuResult.status === 'ecdh_key_mismatch') {
                console.error(`[KEK Distribution] Sender ECDH key mismatch for workspace ${workspaceId}`)
                continue // Skip this workspace
              }
              if (kekSenderTofuResult.status === 'identity_key_changed') {
                console.error(`[KEK Distribution] Sender identity key changed for workspace ${workspaceId}`)
                continue // Skip this workspace
              }
              await handleTofuResult(kekSenderTofuResult)
            }

            // Anti-rollback: check KEK version before decrypting/distributing
            const kekRollback = await checkKeyVersionRollback('kek', workspaceId, existingKey.key_version)
            if (kekRollback.rolledBack) {
              console.error(`[KEK Distribution] Rollback detected for workspace ${workspaceId}: v${existingKey.key_version} < pinned v${kekRollback.pinnedVersion}`)
              continue // Skip this workspace
            }

            // Decrypt KEK with current device's ECDH
            const decryptedKek = decryptKekFromDevice(
              existingEncryptedKek,
              existingNonce,
              currentDevice.deviceKeys.ecdhPrivateKey,
              senderEcdhPk,
              workspaceId,
              auth.userId,
              senderDeviceId,
              currentDevice.deviceId
            )

            await pinKeyVersion({
              type: 'kek',
              id: workspaceId,
              highestVersion: existingKey.key_version,
              observedAt: Date.now(),
            })

            // Re-encrypt KEK for new device using ECDH
            const { encryptedKek: newEncryptedKek, nonce: newKekNonce } = encryptKekForDevice(
              decryptedKek,
              currentDevice.deviceKeys.ecdhPrivateKey,
              pendingDeviceKeys.ecdhPk,
              workspaceId,
              auth.userId,
              currentDevice.deviceId,
              approveResponse.id
            )

            // Save KEK for new device (same version as existing key)
            console.log('[KEK Distribution] Saving KEK for new device, workspace:', workspaceId)
            await encryptionApi.saveWorkspaceKey(workspaceId, {
              device_id: approveResponse.id,
              sender_device_id: currentDevice.deviceId,
              key_version: existingKey.key_version,
              encrypted_kek: base64UrlEncode(newEncryptedKek),
              nonce: base64UrlEncode(newKekNonce),
              is_active: true,
            })
            console.log('[KEK Distribution] Successfully saved KEK for workspace:', workspaceId)
          } catch (err) {
            // Skip workspaces where we don't have KEK yet (might be new workspace)
            if (err instanceof ApiError && err.status === 404) {
              // Anti-rollback: if we previously observed a KEK version, 404 is suspicious
              const existingKekPin = await getKeyVersionPin('kek', workspaceId)
              if (existingKekPin) {
                console.error(`[KEK Distribution] Rollback detected for workspace ${workspaceId}: server returned 404 but v${existingKekPin.highestVersion} was previously observed`)
              } else {
                console.log('[KEK Distribution] No existing KEK for workspace (404):', workspaceId)
              }
            } else {
              console.error(`[KEK Distribution] Failed to distribute KEK for workspace ${workspaceId}:`, err)
            }
          }
        }
        console.log('[KEK Distribution] Completed')
      } catch (err) {
        // Log but don't fail approval - KEK can be distributed on-demand
        console.error('[KEK Distribution] Failed to distribute KEKs:', err)
      }

      // Distribute UMK to new device — this triggers the SSE `pending_approved` event
      // that tells the new device it can proceed. KEKs are already on the server.
      // Encrypt UMK using ECDH: existing device's ECDH private key + new device's ECDH public key
      // Note: Must use device ECDH keys (not identity ECDH keys) because backend returns
      // sender's device ECDH public key for the receiver to derive the shared secret
      const { encryptedUmk, nonce } = encryptUmkForDevice(
        auth.umk,
        currentDevice.deviceKeys.ecdhPrivateKey,
        pendingDeviceKeys.ecdhPk,
        auth.userId,
        currentDevice.deviceId,
        approveResponse.id
      )

      await deviceApi.distributeUmk(approveResponse.id, {
        sender_device_id: currentDevice.deviceId,
        encrypted_umk: base64UrlEncode(encryptedUmk),
        nonce: base64UrlEncode(nonce),
      })

      // Trust State Transfer: Wait for new device to request nonce, then submit trust state
      // This is non-blocking - we continue even if it fails
      try {
        console.log('[Trust Transfer] Waiting for new device to request nonce...')

        // Create a promise that resolves when we receive the TrustTransferNonceReady event
        const waitForNonce = new Promise<{ nonce: string; newDeviceId: string }>((resolve, reject) => {
          const eventSource = new EventSource(
            sseUrls.deviceEvents(),
            { withCredentials: true }
          )

          const timeoutId = setTimeout(() => {
            eventSource.close()
            reject(new Error('Timeout waiting for trust transfer nonce'))
          }, 10000) // 10 second timeout

          eventSource.onmessage = (event) => {
            try {
              const data = JSON.parse(event.data)
              if (data.type === 'trust_transfer_nonce_ready' && data.new_device_id === approveResponse.id) {
                clearTimeout(timeoutId)
                eventSource.close()
                resolve({ nonce: data.nonce, newDeviceId: data.new_device_id })
              }
            } catch {
              // Ignore parse errors
            }
          }

          eventSource.onerror = () => {
            clearTimeout(timeoutId)
            eventSource.close()
            reject(new Error('SSE connection error'))
          }
        })

        const { nonce: nonceBase64, newDeviceId } = await waitForNonce
        console.log('[Trust Transfer] Received nonce for device:', newDeviceId)

        // Get all TOFU entries for this user
        const tofuEntries = await getAllTofuEntriesForUser(auth.userId)
        console.log('[Trust Transfer] TOFU entries to transfer:', tofuEntries.length)

        if (tofuEntries.length > 0) {
          // Encrypt trust state
          const transferNonce = base64UrlDecode(nonceBase64)
          const snapshot = {
            tofuEntries,
            transferNonce,
          }

          const encrypted = encryptTrustState(
            snapshot,
            currentDevice.deviceKeys.ecdhPrivateKey,
            pendingDeviceKeys.ecdhPk,
            currentDevice.deviceKeys.signingPrivateKey,
            {
              userId: auth.userId,
              senderDeviceId: currentDevice.deviceId,
              targetDeviceId: newDeviceId,
            }
          )

          // Submit encrypted trust state
          await trustTransferApi.submitState({
            target_device_id: newDeviceId,
            transfer_nonce: nonceBase64,
            ciphertext: base64UrlEncode(encrypted.encryptedState),
            nonce: base64UrlEncode(encrypted.nonce),
            signature: base64UrlEncode(encrypted.signature),
          })
          console.log('[Trust Transfer] Successfully submitted trust state')
        } else {
          console.log('[Trust Transfer] No TOFU entries to transfer')
        }
      } catch (err) {
        // Log but don't fail approval - trust transfer is optional
        console.warn('[Trust Transfer] Failed:', err)
      }

      onApproved()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to approve device')
      setStep('error')
    }
  }

  const handleReject = async () => {
    try {
      await deviceApi.rejectPendingDevice(device.id)
    } catch {
      // Ignore errors - SSE will handle state update
    }
    onClose()
  }

  // Key change warning handlers
  const handleKeyChangeTrust = async () => {
    if (!keyChangeWarning || !pendingDeviceKeys || !auth?.userId) return

    // Store the pending trust - will be persisted after approve success
    setPendingKeyChangeTrust(keyChangeWarning.tofuResult)
    setKeyChangeWarning(null)

    // Continue to SAS verification
    const emojis = generateSasEmojis(
      auth.identityKeys!.signingPublic,
      pendingDeviceKeys.signingPk,
      pendingDeviceKeys.ecdhPk,
      pendingDeviceKeys.clientNonce
    )
    setSasEmojis(emojis)
    setStep('verify')
  }

  const handleKeyChangeBlock = async () => {
    // Block/reject the device
    try {
      await deviceApi.rejectPendingDevice(device.id)
    } catch {
      // Ignore errors
    }
    setKeyChangeWarning(null)
    onClose()
  }

  const handleKeyChangeCancel = () => {
    setKeyChangeWarning(null)
    onClose()
  }

  // Show key change warning dialog if needed
  if (keyChangeWarning) {
    return (
      <KeyChangeWarningDialog
        open={true}
        deviceName={device.name}
        oldFingerprint={keyChangeWarning.oldFingerprint}
        newFingerprint={keyChangeWarning.newFingerprint}
        onTrust={handleKeyChangeTrust}
        onBlock={handleKeyChangeBlock}
        onCancel={handleKeyChangeCancel}
      />
    )
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New Device Request</DialogTitle>
          <DialogDescription>
            A new device wants to access your account
          </DialogDescription>
        </DialogHeader>

        {/* Device Info */}
        <div className="rounded-lg border bg-muted/50 p-4 space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Device</span>
            <span className="font-medium">{device.name}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Type</span>
            <span className="font-medium capitalize">{device.device_type}</span>
          </div>
          {device.ip_address && (
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">IP Address</span>
              <span className="font-medium font-mono">{device.ip_address}</span>
            </div>
          )}
        </div>

        <div className="space-y-4">
          {step === 'loading' && (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
            </div>
          )}

          {step === 'verify' && sasEmojis && (
            <>
              <SasVerification emojis={sasEmojis} role="existing" />

              <div className="flex gap-3">
                <Button className="flex-1" onClick={handleApprove}>
                  Approve
                </Button>
                <Button variant="destructive" className="flex-1" onClick={handleReject}>
                  Reject
                </Button>
              </div>
            </>
          )}

          {step === 'approving' && (
            <div className="flex flex-col items-center gap-4 py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
              <p className="text-sm text-muted-foreground">Approving device…</p>
            </div>
          )}

          {step === 'error' && (
            <div className="space-y-4">
              <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                {error}
              </div>
              <div className="flex gap-3">
                <Button variant="outline" className="flex-1" onClick={loadSas}>
                  Retry
                </Button>
                <Button variant="ghost" className="flex-1" onClick={onClose}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
