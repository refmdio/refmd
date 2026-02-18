import { Button } from '@/shared/ui/button'
import { Spinner } from '@/shared/ui/spinner'
import { DeviceIcon } from '@/shared/ui/DeviceIcon'
import { ErrorAlert } from '@/shared/ui/error-alert'
import { Trash2, AlertTriangle } from 'lucide-react'

interface TrustedDevicesListProps {
  devices: Array<{ id: string; name: string; device_type: string; is_current: boolean; last_seen_at: string }>
  loading: boolean
  error: string | null
  compromisedDevices: Set<string>
  devicesWithKeyChange: Set<string>
  rotatingKek: boolean
  onRevokeRequest: (deviceId: string) => void
}

export function TrustedDevicesList({
  devices,
  loading,
  error,
  compromisedDevices,
  devicesWithKeyChange,
  rotatingKek,
  onRevokeRequest,
}: TrustedDevicesListProps) {
  return (
    <section>
      <h4 className="text-sm font-medium mb-3">Trusted Devices</h4>
      {loading ? (
        <div className="flex justify-center py-8">
          <Spinner />
        </div>
      ) : error ? (
        <ErrorAlert>{error}</ErrorAlert>
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
                    onClick={() => onRevokeRequest(device.id)}
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
  )
}
