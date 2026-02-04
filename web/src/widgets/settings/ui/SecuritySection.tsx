/**
 * Security Section
 *
 * Trusted devices management.
 */

import { useState, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { deviceApi } from '@/shared/api'
import { usePendingDevices } from '@/features/device'
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
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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

    try {
      await deviceApi.revokeDevice(deviceId)
      await loadDevices()
    } catch (err) {
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
