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
import { deviceApi, workspaceApi, encryptionApi, ApiError } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateSasEmojis,
  sign,
  encryptUmkForDevice,
  decryptKekFromDevice,
  encryptKekForDevice,
} from '@/shared/lib/crypto'

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
  const cancelledRef = useRef(false)

  // Load SAS function (reusable for retry)
  const loadSas = useCallback(async () => {
    if (!auth?.identityKeys) {
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

      // Store for approval
      setPendingDeviceKeys({
        signingPk: deviceSigningPk,
        ecdhPk: deviceEcdhPk,
        clientNonce: clientNonce,
      })

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
  }, [device.id, auth?.identityKeys])

  // Load SAS on mount with cancellation support
  useEffect(() => {
    cancelledRef.current = false
    loadSas()

    return () => {
      cancelledRef.current = true
    }
  }, [loadSas])

  const handleApprove = async () => {
    if (!auth?.identityKeys || !auth?.umk || !currentDevice || !pendingDeviceKeys) {
      setError('Missing required keys or device info')
      setStep('error')
      return
    }

    try {
      setStep('approving')
      setError(null)

      // Build the message to sign: device_signing_pk || device_ecdh_pk || client_nonce
      const message = new Uint8Array(32 + 32 + 16)
      message.set(pendingDeviceKeys.signingPk, 0)
      message.set(pendingDeviceKeys.ecdhPk, 32)
      message.set(pendingDeviceKeys.clientNonce, 64)

      // Sign with identity signing key
      const signature = sign(message, auth.identityKeys.signingPrivate)

      // Send approval - returns the new device ID
      const approveResponse = await deviceApi.approveDevice(device.id, {
        identity_signature: base64UrlEncode(signature),
      })

      // Distribute UMK to new device
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
        pending_device_id: device.id,
        encrypted_umk: base64UrlEncode(encryptedUmk),
        nonce: base64UrlEncode(nonce),
      })

      // Distribute KEKs for all workspaces the user has access to
      // This is required because KEKs are wrapped per-device
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

            // Save KEK for new device
            console.log('[KEK Distribution] Saving KEK for new device, workspace:', workspaceId)
            await encryptionApi.saveWorkspaceKey(workspaceId, {
              device_id: approveResponse.id,
              sender_device_id: currentDevice.deviceId,
              encrypted_kek: base64UrlEncode(newEncryptedKek),
              nonce: base64UrlEncode(newKekNonce),
              is_active: true,
            })
            console.log('[KEK Distribution] Successfully saved KEK for workspace:', workspaceId)
          } catch (err) {
            // Skip workspaces where we don't have KEK yet (might be new workspace)
            if (!(err instanceof ApiError && err.status === 404)) {
              console.error(`[KEK Distribution] Failed to distribute KEK for workspace ${workspaceId}:`, err)
            } else {
              console.log('[KEK Distribution] No existing KEK for workspace (404):', workspaceId)
            }
          }
        }
        console.log('[KEK Distribution] Completed')
      } catch (err) {
        // Log but don't fail approval - KEK can be distributed on-demand
        console.error('[KEK Distribution] Failed to distribute KEKs:', err)
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
