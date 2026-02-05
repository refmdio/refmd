/**
 * Security Section
 *
 * Trusted devices management.
 */

import { useState, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { deviceApi, encryptionApi, ApiError } from '@/shared/api'
import { usePendingDevices } from '@/features/device'
import { useAuthContext } from '@/shared/context/AuthContext'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateKek,
  encryptKekForDevice,
} from '@/shared/lib/crypto'
import { Monitor, Smartphone, Globe, Trash2 } from 'lucide-react'

interface Device {
  id: string
  name: string
  device_type: string
  last_seen_at: string
  created_at: string
  is_current: boolean
}

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

  useEffect(() => {
    loadDevices()
  }, [])

  const loadDevices = async () => {
    try {
      setLoading(true)
      setError(null)
      const response = await deviceApi.listDevices()
      setDevices(response.devices)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load devices')
    } finally {
      setLoading(false)
    }
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
      // Revoke device and get workspaces needing KEK rotation
      const response = await deviceApi.revokeDevice(deviceId)
      const workspacesToRotate = response?.workspaces_needing_kek_rotation || []

      // Perform KEK rotation for each workspace
      if (workspacesToRotate.length > 0) {
        setRotatingKek(true)
        console.log('[KEK Rotation] Starting rotation for workspaces:', workspacesToRotate)

        // Get list of remaining active devices (excluding revoked one)
        const devicesResponse = await deviceApi.listDevices()
        const activeDevices = devicesResponse.devices.filter(d => d.id !== deviceId)

        for (const workspaceId of workspacesToRotate) {
          try {
            // Get current KEK to determine version
            const existingKey = await encryptionApi.getWorkspaceKey(workspaceId, currentDevice.deviceId)
            const currentVersion = existingKey.key_version
            const newVersion = currentVersion + 1

            // Generate new KEK for rotation (don't reuse old one - forward secrecy)
            const newKek = generateKek()
            console.log('[KEK Rotation] Generated new KEK for workspace:', workspaceId)

            // Distribute new KEK to all active devices
            for (const targetDevice of activeDevices) {
              try {
                // Get target device's ECDH public key from device list response
                const targetEcdhPk = base64UrlDecode(targetDevice.ecdh_public_key)

                // Encrypt new KEK for target device
                const { encryptedKek, nonce } = encryptKekForDevice(
                  newKek,
                  currentDevice.deviceKeys.ecdhPrivateKey,
                  targetEcdhPk,
                  workspaceId,
                  auth.userId,
                  currentDevice.deviceId,
                  targetDevice.id
                )

                // Save new KEK for target device
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

            // Complete KEK rotation
            await encryptionApi.completeKekRotation(workspaceId, newVersion)
            console.log('[KEK Rotation] Completed rotation for workspace:', workspaceId)
          } catch (err) {
            if (!(err instanceof ApiError && err.status === 404)) {
              console.error('[KEK Rotation] Failed for workspace:', workspaceId, err)
            }
          }
        }
        setRotatingKek(false)
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
            {devices.map((device) => (
              <div
                key={device.id}
                className="flex items-center justify-between p-3 rounded border border-border/60 bg-card"
              >
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded bg-muted text-muted-foreground">
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
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Last active {new Date(device.last_seen_at).toLocaleDateString()}
                    </p>
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
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
