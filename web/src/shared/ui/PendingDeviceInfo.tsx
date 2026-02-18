import { DeviceIcon } from '@/shared/ui/DeviceIcon'
import type { PendingDevice } from '@/shared/api'

interface PendingDeviceInfoProps {
  device: PendingDevice
  /** Additional text shown below name/ip (e.g. expiry or time ago) */
  subtitle?: React.ReactNode
}

export function PendingDeviceInfo({ device, subtitle }: PendingDeviceInfoProps) {
  return (
    <div className="flex items-center gap-3">
      <div className="p-1.5 rounded bg-yellow-500/10 text-yellow-600">
        <DeviceIcon type={device.device_type} />
      </div>
      <div className="min-w-0">
        <p className="text-sm font-medium truncate">{device.name}</p>
        {device.ip_address && (
          <p className="text-xs text-muted-foreground font-mono truncate">{device.ip_address}</p>
        )}
        {subtitle}
      </div>
    </div>
  )
}
