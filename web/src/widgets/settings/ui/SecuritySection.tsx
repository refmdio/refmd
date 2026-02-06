/**
 * Security Section
 *
 * Trusted devices management.
 */

import { useState, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { deviceApi, encryptionApi, ApiError } from '@/shared/api'
import type { components } from '@/shared/api/schema'
import { usePendingDevices } from '@/features/device'
import { useAuthContext } from '@/shared/context/AuthContext'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateDek,
  generateKek,
  encryptKekForDevice,
  wrapKekWithUmk,
  wrapDek,
  verifyTofu,
  handleTofuResult,
  trustDevice,
  sign,
  buildSignatureMessage,
  SIGNATURE_ACTION,
} from '@/shared/lib/crypto'
import { KeyChangeWarningDialog } from '@/features/tofu'
import { Monitor, Smartphone, Globe, Trash2, AlertTriangle } from 'lucide-react'

type Device = components['schemas']['DeviceResponse']
type WorkspaceDocumentsForRotation = components['schemas']['WorkspaceDocumentsForRotationResponse']

interface PendingDevice {
  id: string
  name: string
  device_type: string
  ip_address?: string | null
  created_at: string
  expires_at: string
}

interface SecuritySectionProps {
  onClose: () => void
}

function DeviceIcon({ type }: { type: string }) {
  switch (type) {
    case 'mobile':
      return <Smartphone className="h-4 w-4" aria-hidden="true" />
    case 'desktop':
      return <Monitor className="h-4 w-4" aria-hidden="true" />
    default:
      return <Globe className="h-4 w-4" aria-hidden="true" />
  }
}

export function SecuritySection({ onClose }: SecuritySectionProps) {
  const { pendingDevices, showApprovalDialog } = usePendingDevices()
  const { auth, device: currentDevice } = useAuthContext()
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [rotatingKek, setRotatingKek] = useState(false)
  const [kekRotationWarning, setKekRotationWarning] = useState<string | null>(null)
  const [compromisedDevices, setCompromisedDevices] = useState<Set<string>>(new Set())
  // Queue of devices with identity key changes pending user confirmation
  const [identityKeyChangeQueue, setIdentityKeyChangeQueue] = useState<Array<{
    device: Device
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
  }>>([])
  // Track devices with confirmed identity key changes
  const [devicesWithKeyChange, setDevicesWithKeyChange] = useState<Set<string>>(new Set())
  // KEK rotation pending confirmation for devices with key changes
  const [kekRotationPending, setKekRotationPending] = useState<{
    deviceIdToRevoke: string
    devicesWithKeyChange: Array<{
      device: Device
      oldFingerprint: string
      newFingerprint: string
      tofuResult: Awaited<ReturnType<typeof verifyTofu>>
    }>
    workspacesToRotate: string[]
    documentsForRotation: WorkspaceDocumentsForRotation[]
  } | null>(null)
  // Current device being confirmed during KEK rotation
  const [kekRotationCurrentDevice, setKekRotationCurrentDevice] = useState<{
    device: Device
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
  } | null>(null)
  // Devices confirmed during KEK rotation (will receive new KEK)
  const [kekRotationTrustedDevices, setKekRotationTrustedDevices] = useState<Set<string>>(new Set())
  // Unexpected key change during KEK distribution (device not in pre-check)
  const [kekDistributionKeyChange, setKekDistributionKeyChange] = useState<{
    device: Device
    oldFingerprint: string
    newFingerprint: string
    tofuResult: Awaited<ReturnType<typeof verifyTofu>>
    // Context to resume rotation
    pendingContext: {
      revokedDeviceId: string
      workspacesToRotate: string[]
      trustedDeviceIds: Set<string>
      documentsForRotation: WorkspaceDocumentsForRotation[]
    }
  } | null>(null)

  useEffect(() => {
    loadDevices()
  }, [])

  const loadDevices = async () => {
    if (!auth?.userId) return

    try {
      setLoading(true)
      setError(null)
      const response = await deviceApi.listDevices()

      // TOFU verification for each device
      const detectedCompromised = new Set<string>()
      const keyChangeQueue: Array<{
        device: Device
        oldFingerprint: string
        newFingerprint: string
        tofuResult: Awaited<ReturnType<typeof verifyTofu>>
      }> = []

      for (const device of response.devices) {
        if (device.signing_public_key && device.ecdh_public_key) {
          try {
            const signingPk = base64UrlDecode(device.signing_public_key)
            const ecdhPk = base64UrlDecode(device.ecdh_public_key)
            const tofuResult = await verifyTofu(auth.userId, device.id, signingPk, ecdhPk)

            if (tofuResult.status === 'ecdh_key_mismatch') {
              console.error('[TOFU] ECDH key mismatch for device:', device.id)
              // Mark device as potentially compromised and abort immediately
              detectedCompromised.add(device.id)
              setCompromisedDevices(detectedCompromised)
              setDevices(response.devices)
              setError(`Security alert: Device "${device.name}" has a key mismatch. This may indicate tampering. Consider revoking this device immediately.`)
              setLoading(false)
              return // Abort device list processing - security issue detected
            }

            if (tofuResult.status === 'identity_key_changed') {
              // Queue for user confirmation dialog
              keyChangeQueue.push({
                device,
                oldFingerprint: tofuResult.oldFingerprint!,
                newFingerprint: tofuResult.newFingerprint!,
                tofuResult,
              })
              continue
            }

            // Handle first_seen and known_trusted automatically
            if (tofuResult.status === 'first_seen' || tofuResult.status === 'known_trusted') {
              await handleTofuResult(tofuResult)
            }
          } catch (err) {
            console.error('[TOFU] Verification failed for device:', device.id, err)
          }
        }
      }

      setCompromisedDevices(detectedCompromised)
      setIdentityKeyChangeQueue(keyChangeQueue)
      setDevices(response.devices)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load devices')
    } finally {
      setLoading(false)
    }
  }

  // Perform actual KEK rotation with the set of trusted devices
  const performKekRotation = async (
    revokedDeviceId: string,
    workspacesToRotate: string[],
    trustedDeviceIds: Set<string>,
    documentsForRotation: WorkspaceDocumentsForRotation[]
  ) => {
    if (!auth || !currentDevice) return

    setRotatingKek(true)
    setKekRotationWarning(null)

    const devicesResponse = await deviceApi.listDevices()
    const activeDevices = devicesResponse.devices.filter(d => d.id !== revokedDeviceId)
    const devicesSkippedKeyChange: string[] = []
    const devicesWithEcdhMismatch: string[] = []

    for (const workspaceId of workspacesToRotate) {
      try {
        const existingKey = await encryptionApi.getWorkspaceKey(workspaceId, currentDevice.deviceId)
        const currentVersion = existingKey.key_version
        const newVersion = currentVersion + 1

        const newKek = generateKek()
        console.log('[KEK Rotation] Generated new KEK for workspace:', workspaceId)

        for (const targetDevice of activeDevices) {
          try {
            if (targetDevice.signing_public_key && targetDevice.ecdh_public_key) {
              const signingPk = base64UrlDecode(targetDevice.signing_public_key)
              const ecdhPk = base64UrlDecode(targetDevice.ecdh_public_key)
              const tofuResult = await verifyTofu(auth.userId, targetDevice.id, signingPk, ecdhPk)

              if (tofuResult.status === 'ecdh_key_mismatch') {
                // ECDH mismatch is a critical security issue - abort the entire rotation
                console.error('[KEK Distribution] ECDH key mismatch for device:', targetDevice.id)
                setRotatingKek(false)
                setError(`KEK rotation aborted: Device "${targetDevice.name}" has a suspicious key mismatch. This may indicate a security issue.`)
                await loadDevices()
                return
              }

              if (tofuResult.status === 'identity_key_changed') {
                // Only distribute to trusted devices (pre-checked by user)
                if (!trustedDeviceIds.has(targetDevice.id)) {
                  // This device wasn't in pre-check - show dialog for user confirmation
                  console.warn('[KEK Distribution] Unexpected identity_key_changed for device:', targetDevice.id)
                  setRotatingKek(false)
                  setKekDistributionKeyChange({
                    device: targetDevice,
                    oldFingerprint: tofuResult.oldFingerprint!,
                    newFingerprint: tofuResult.newFingerprint!,
                    tofuResult,
                    pendingContext: {
                      revokedDeviceId,
                      workspacesToRotate,
                      trustedDeviceIds: new Set([...trustedDeviceIds]),
                      documentsForRotation,
                    },
                  })
                  return // Pause rotation, wait for user confirmation
                }
                // User trusted this device, save the new entry
                await trustDevice(tofuResult.newEntry)
              } else {
                await handleTofuResult(tofuResult)
              }
            }

            const targetEcdhPk = base64UrlDecode(targetDevice.ecdh_public_key)
            const { encryptedKek, nonce } = encryptKekForDevice(
              newKek,
              currentDevice.deviceKeys.ecdhPrivateKey,
              targetEcdhPk,
              workspaceId,
              auth.userId,
              currentDevice.deviceId,
              targetDevice.id
            )

            await encryptionApi.saveWorkspaceKey(workspaceId, {
              device_id: targetDevice.id,
              sender_device_id: currentDevice.deviceId,
              key_version: newVersion,
              encrypted_kek: base64UrlEncode(encryptedKek),
              nonce: base64UrlEncode(nonce),
              is_active: true,
            })
            console.log('[KEK Rotation] Distributed new KEK to device:', targetDevice.id)
          } catch (err) {
            console.error('[KEK Rotation] Failed to distribute KEK to device:', targetDevice.id, err)
          }
        }

        // Save UMK backup BEFORE completing rotation (mandatory step)
        // If backup fails, abort rotation to prevent recovery-unreachable KEK
        if (auth.umk) {
          const { encryptedKek: bkpKek, nonce: bkpNonce } = wrapKekWithUmk(
            newKek, auth.umk, workspaceId, auth.userId, newVersion
          )
          await encryptionApi.saveWorkspaceKekBackup(workspaceId, {
            key_version: newVersion,
            encrypted_kek: base64UrlEncode(bkpKek),
            nonce: base64UrlEncode(bkpNonce),
          })
          console.log('[KEK Rotation] Saved UMK backup for workspace:', workspaceId)
        }

        await encryptionApi.completeKekRotation(workspaceId, newVersion)
        console.log('[KEK Rotation] Completed rotation for workspace:', workspaceId)

        // DEK rotation: generate new DEK for each document in this workspace
        const wsRotation = documentsForRotation.find(r => r.workspace_id === workspaceId)
        if (wsRotation) {
          for (const documentId of wsRotation.document_ids) {
            try {
              const newDek = generateDek()
              const { encryptedDek, nonce: dekNonce } = wrapDek(newDek, newKek, documentId, workspaceId)
              await encryptionApi.saveDocumentKey(documentId, {
                encrypted_dek: base64UrlEncode(encryptedDek),
                nonce: base64UrlEncode(dekNonce),
                is_active: true,
              })
            } catch (err) {
              console.error('[DEK Rotation] Failed for document:', documentId, err)
            }
          }
        }
      } catch (err) {
        if (!(err instanceof ApiError && err.status === 404)) {
          console.error('[KEK Rotation] Failed for workspace:', workspaceId, err)
        }
      }
    }

    setRotatingKek(false)

    const warnings: string[] = []
    if (devicesSkippedKeyChange.length > 0) {
      warnings.push(
        `${devicesSkippedKeyChange.length} device(s) skipped due to key change: ${devicesSkippedKeyChange.join(', ')}`
      )
    }
    if (devicesWithEcdhMismatch.length > 0) {
      warnings.push(
        `${devicesWithEcdhMismatch.length} device(s) with suspicious key mismatch: ${devicesWithEcdhMismatch.join(', ')}`
      )
    }
    if (warnings.length > 0) {
      setKekRotationWarning(`Key rotation skipped for:\n${warnings.join('\n')}`)
    }

    await loadDevices()
  }

  const handleRevokeDevice = async (deviceId: string) => {
    if (!confirm('Are you sure you want to revoke this device? It will need to be re-approved to access your account.')) {
      return
    }

    if (!auth || !currentDevice) {
      setError('Authentication required')
      return
    }

    try {
      // Create revocation signature using JCS (JSON Canonicalization Scheme)
      const revokedAt = Date.now()

      // Build JCS signature message for device revocation
      const message = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_REVOCATION, {
        user_id: auth.userId,
        device_id: deviceId,
        revoked_at: revokedAt,
        revoked_by_device_id: currentDevice.deviceId,
      })

      // Sign with identity key
      if (!auth.identityKeys) {
        throw new Error('Identity keys not available')
      }
      const signature = sign(message, auth.identityKeys.signingPrivate)

      // Revoke device and get workspaces/documents needing key rotation
      const response = await deviceApi.revokeDevice(deviceId, {
        identity_signature: base64UrlEncode(signature),
        revoked_at: revokedAt,
      })
      const workspacesToRotate = response?.workspaces_needing_kek_rotation || []
      const documentsForRotation: WorkspaceDocumentsForRotation[] = response?.documents_needing_dek_rotation || []

      // Perform KEK rotation for each workspace
      if (workspacesToRotate.length > 0) {
        console.log('[KEK Rotation] Starting rotation for workspaces:', workspacesToRotate)

        // Get list of remaining active devices (excluding revoked one)
        const devicesResponse = await deviceApi.listDevices()
        const activeDevices = devicesResponse.devices.filter(d => d.id !== deviceId)

        // Pre-check all devices for identity key changes
        const keyChangeDevices: Array<{
          device: Device
          oldFingerprint: string
          newFingerprint: string
          tofuResult: Awaited<ReturnType<typeof verifyTofu>>
        }> = []

        for (const targetDevice of activeDevices) {
          if (targetDevice.signing_public_key && targetDevice.ecdh_public_key) {
            try {
              const signingPk = base64UrlDecode(targetDevice.signing_public_key)
              const ecdhPk = base64UrlDecode(targetDevice.ecdh_public_key)
              const tofuResult = await verifyTofu(auth.userId, targetDevice.id, signingPk, ecdhPk)

              if (tofuResult.status === 'ecdh_key_mismatch') {
                // ECDH mismatch - abort before rotation even starts
                setError(`KEK rotation aborted: Device "${targetDevice.name}" has a suspicious key mismatch. Revoke this device first.`)
                return
              }

              if (tofuResult.status === 'identity_key_changed') {
                keyChangeDevices.push({
                  device: targetDevice,
                  oldFingerprint: tofuResult.oldFingerprint!,
                  newFingerprint: tofuResult.newFingerprint!,
                  tofuResult,
                })
              }
            } catch (err) {
              console.error('[KEK Rotation] TOFU check failed for device:', targetDevice.id, err)
            }
          }
        }

        // If there are devices with key changes, show dialogs before proceeding
        if (keyChangeDevices.length > 0) {
          setKekRotationPending({
            deviceIdToRevoke: deviceId,
            devicesWithKeyChange: keyChangeDevices,
            workspacesToRotate,
            documentsForRotation,
          })
          // Show first device dialog
          setKekRotationCurrentDevice(keyChangeDevices[0])
          setKekRotationTrustedDevices(new Set())
          return // Wait for user to confirm each device
        }

        // No key changes, proceed with rotation directly
        await performKekRotation(deviceId, workspacesToRotate, new Set(), documentsForRotation)
      }

      await loadDevices()
    } catch (err) {
      setRotatingKek(false)
      setError(err instanceof Error ? err.message : 'Failed to revoke device')
    }
  }

  const handleReviewPending = (device: PendingDevice) => {
    onClose()
    setTimeout(() => showApprovalDialog(device), 100)
  }

  // Identity key change dialog handlers
  const currentKeyChangeItem = identityKeyChangeQueue[0]

  const handleIdentityKeyChangeTrust = async () => {
    if (!currentKeyChangeItem) return

    // Trust the new key
    await trustDevice(currentKeyChangeItem.tofuResult.newEntry)

    // Track that this device was trusted after key change
    setDevicesWithKeyChange(prev => new Set([...prev, currentKeyChangeItem.device.id]))

    // Remove from queue
    setIdentityKeyChangeQueue(prev => prev.slice(1))
  }

  const handleIdentityKeyChangeBlock = async () => {
    if (!currentKeyChangeItem) return

    // Mark as compromised (user chose to block)
    setCompromisedDevices(prev => new Set([...prev, currentKeyChangeItem.device.id]))

    // Remove from queue
    setIdentityKeyChangeQueue(prev => prev.slice(1))
  }

  const handleIdentityKeyChangeCancel = () => {
    // Skip all remaining - mark as needing attention
    for (const item of identityKeyChangeQueue) {
      setDevicesWithKeyChange(prev => new Set([...prev, item.device.id]))
    }
    setIdentityKeyChangeQueue([])
  }

  // KEK rotation key change dialog handlers
  const handleKekRotationTrust = async () => {
    if (!kekRotationCurrentDevice || !kekRotationPending) return

    // Add to trusted devices
    setKekRotationTrustedDevices(prev => new Set([...prev, kekRotationCurrentDevice.device.id]))

    // Move to next device or complete rotation
    const currentIndex = kekRotationPending.devicesWithKeyChange.findIndex(
      d => d.device.id === kekRotationCurrentDevice.device.id
    )
    const nextDevice = kekRotationPending.devicesWithKeyChange[currentIndex + 1]

    if (nextDevice) {
      setKekRotationCurrentDevice(nextDevice)
    } else {
      // All devices processed, proceed with rotation
      const trustedIds = new Set([...kekRotationTrustedDevices, kekRotationCurrentDevice.device.id])
      setKekRotationCurrentDevice(null)
      const pending = kekRotationPending
      setKekRotationPending(null)
      await performKekRotation(pending.deviceIdToRevoke, pending.workspacesToRotate, trustedIds, pending.documentsForRotation)
    }
  }

  const handleKekRotationBlock = async () => {
    if (!kekRotationCurrentDevice || !kekRotationPending) return

    // Move to next device or complete rotation (device not added to trusted set)
    const currentIndex = kekRotationPending.devicesWithKeyChange.findIndex(
      d => d.device.id === kekRotationCurrentDevice.device.id
    )
    const nextDevice = kekRotationPending.devicesWithKeyChange[currentIndex + 1]

    if (nextDevice) {
      setKekRotationCurrentDevice(nextDevice)
    } else {
      // All devices processed, proceed with rotation
      setKekRotationCurrentDevice(null)
      const pending = kekRotationPending
      const trustedIds = kekRotationTrustedDevices
      setKekRotationPending(null)
      await performKekRotation(pending.deviceIdToRevoke, pending.workspacesToRotate, trustedIds, pending.documentsForRotation)
    }
  }

  const handleKekRotationCancel = async () => {
    // Skip all remaining dialogs and proceed with rotation using only trusted so far
    if (!kekRotationPending) return

    setKekRotationCurrentDevice(null)
    const pending = kekRotationPending
    const trustedIds = kekRotationTrustedDevices
    setKekRotationPending(null)
    await performKekRotation(pending.deviceIdToRevoke, pending.workspacesToRotate, trustedIds, pending.documentsForRotation)
  }

  // KEK distribution key change handlers (for unexpected key changes during distribution)
  const handleKekDistributionTrust = async () => {
    if (!kekDistributionKeyChange) return

    // Trust the new key
    await trustDevice(kekDistributionKeyChange.tofuResult.newEntry)

    // Resume rotation with this device now trusted
    const { pendingContext } = kekDistributionKeyChange
    const newTrustedIds = new Set([...pendingContext.trustedDeviceIds, kekDistributionKeyChange.device.id])
    setKekDistributionKeyChange(null)
    await performKekRotation(pendingContext.revokedDeviceId, pendingContext.workspacesToRotate, newTrustedIds, pendingContext.documentsForRotation)
  }

  const handleKekDistributionBlock = async () => {
    if (!kekDistributionKeyChange) return

    // Don't trust - skip this device and resume rotation
    const { pendingContext } = kekDistributionKeyChange
    setKekDistributionKeyChange(null)
    await performKekRotation(pendingContext.revokedDeviceId, pendingContext.workspacesToRotate, pendingContext.trustedDeviceIds, pendingContext.documentsForRotation)
  }

  const handleKekDistributionCancel = async () => {
    if (!kekDistributionKeyChange) return

    // Cancel = same as block, skip device and continue
    const { pendingContext } = kekDistributionKeyChange
    setKekDistributionKeyChange(null)
    await performKekRotation(pendingContext.revokedDeviceId, pendingContext.workspacesToRotate, pendingContext.trustedDeviceIds, pendingContext.documentsForRotation)
  }

  // Show KEK distribution key change dialog if needed (unexpected key change during distribution)
  if (kekDistributionKeyChange) {
    return (
      <KeyChangeWarningDialog
        open={true}
        deviceName={kekDistributionKeyChange.device.name}
        oldFingerprint={kekDistributionKeyChange.oldFingerprint}
        newFingerprint={kekDistributionKeyChange.newFingerprint}
        onTrust={handleKekDistributionTrust}
        onBlock={handleKekDistributionBlock}
        onCancel={handleKekDistributionCancel}
      />
    )
  }

  // Show KEK rotation key change dialog if needed
  if (kekRotationCurrentDevice) {
    return (
      <KeyChangeWarningDialog
        open={true}
        deviceName={kekRotationCurrentDevice.device.name}
        oldFingerprint={kekRotationCurrentDevice.oldFingerprint}
        newFingerprint={kekRotationCurrentDevice.newFingerprint}
        onTrust={handleKekRotationTrust}
        onBlock={handleKekRotationBlock}
        onCancel={handleKekRotationCancel}
      />
    )
  }

  // Show identity key change warning dialog if there are pending items
  if (currentKeyChangeItem) {
    return (
      <KeyChangeWarningDialog
        open={true}
        deviceName={currentKeyChangeItem.device.name}
        oldFingerprint={currentKeyChangeItem.oldFingerprint}
        newFingerprint={currentKeyChangeItem.newFingerprint}
        onTrust={handleIdentityKeyChangeTrust}
        onBlock={handleIdentityKeyChangeBlock}
        onCancel={handleIdentityKeyChangeCancel}
      />
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1">Security</h3>
        <p className="text-sm text-muted-foreground">
          Manage your trusted devices and security settings.
        </p>
      </div>

      {/* Pending Devices */}
      {pendingDevices.length > 0 && (
        <section>
          <div className="flex items-center gap-2 mb-3">
            <h4 className="text-sm font-medium">Pending Approval</h4>
            <span className="bg-yellow-500/20 text-yellow-600 text-xs px-2 py-0.5 rounded-full font-medium">
              {pendingDevices.length}
            </span>
          </div>
          <div className="space-y-2">
            {pendingDevices.map((device) => (
              <div
                key={device.id}
                className="flex items-center justify-between p-3 rounded border border-yellow-500/30 bg-yellow-500/5"
              >
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded bg-yellow-500/10 text-yellow-600">
                    <DeviceIcon type={device.device_type} />
                  </div>
                  <div>
                    <p className="text-sm font-medium">{device.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {device.ip_address && <span className="font-mono">{device.ip_address} · </span>}
                      Expires {new Date(device.expires_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
                <Button size="sm" onClick={() => handleReviewPending(device)}>
                  Review
                </Button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* KEK Rotation Status */}
      {rotatingKek && (
        <div className="flex items-center gap-3 p-3 rounded border border-blue-500/30 bg-blue-500/5">
          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500" />
          <span className="text-sm text-blue-600">Rotating encryption keys...</span>
        </div>
      )}

      {/* KEK Rotation Warning */}
      {kekRotationWarning && (
        <div className="p-3 rounded border border-yellow-500/50 bg-yellow-500/10">
          <div className="flex items-start gap-2">
            <span className="text-yellow-600 mt-0.5">⚠️</span>
            <div className="flex-1">
              <p className="text-sm text-yellow-700 dark:text-yellow-500">{kekRotationWarning}</p>
              <button
                className="text-xs text-yellow-600 hover:underline mt-1"
                onClick={() => setKekRotationWarning(null)}
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Trusted Devices */}
      <section>
        <h4 className="text-sm font-medium mb-3">Trusted Devices</h4>
        {loading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary" />
          </div>
        ) : error ? (
          <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
            {error}
          </div>
        ) : devices.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4">No trusted devices</p>
        ) : (
          <div className="space-y-2">
            {devices.map((device) => {
              const isCompromised = compromisedDevices.has(device.id)
              const hasKeyChange = devicesWithKeyChange.has(device.id)
              return (
                <div
                  key={device.id}
                  className={`flex items-center justify-between p-3 rounded border ${
                    isCompromised
                      ? 'border-red-500/50 bg-red-500/5'
                      : 'border-border/60 bg-card'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-1.5 rounded ${
                      isCompromised
                        ? 'bg-red-500/10 text-red-500'
                        : 'bg-muted text-muted-foreground'
                    }`}>
                      <DeviceIcon type={device.device_type} />
                    </div>
                    <div>
                      <p className="text-sm font-medium flex items-center gap-2">
                        {device.name}
                        {device.is_current && (
                          <span className="bg-green-500/20 text-green-600 text-xs px-1.5 py-0.5 rounded font-medium">
                            This device
                          </span>
                        )}
                        {isCompromised && (
                          <span className="bg-red-500/20 text-red-600 text-xs px-1.5 py-0.5 rounded font-medium flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3" />
                            Key mismatch
                          </span>
                        )}
                        {hasKeyChange && !isCompromised && (
                          <span className="bg-amber-500/20 text-amber-600 text-xs px-1.5 py-0.5 rounded font-medium">
                            Key updated
                          </span>
                        )}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Last active {new Date(device.last_seen_at).toLocaleDateString()}
                      </p>
                      {isCompromised && (
                        <p className="text-xs text-red-600 mt-1">
                          Security issue detected. Consider revoking this device.
                        </p>
                      )}
                    </div>
                  </div>
                  {!device.is_current && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-destructive hover:text-destructive hover:bg-destructive/10"
                      onClick={() => handleRevokeDevice(device.id)}
                      disabled={rotatingKek}
                      aria-label={`Revoke device ${device.name}`}
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                    </Button>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}
