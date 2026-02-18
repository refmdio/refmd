import { Button } from '@/shared/ui/button'
import { PendingDeviceInfo } from '@/shared/ui/PendingDeviceInfo'
import { type PendingDevice } from '@/shared/api'

interface PendingDevicesSectionProps {
  devices: PendingDevice[]
  onReview: (device: PendingDevice) => void
}

export function PendingDevicesSection({ devices, onReview }: PendingDevicesSectionProps) {
  if (devices.length === 0) return null

  return (
    <section>
      <div className="flex items-center gap-2 mb-3">
        <h4 className="text-sm font-medium">Pending Approval</h4>
        <span className="bg-yellow-500/20 text-yellow-600 text-xs px-2 py-0.5 rounded-full font-medium">
          {devices.length}
        </span>
      </div>
      <div className="space-y-2">
        {devices.map((device) => (
          <div
            key={device.id}
            className="flex items-center justify-between p-3 rounded border border-yellow-500/30 bg-yellow-500/5"
          >
            <PendingDeviceInfo
              device={device}
              subtitle={
                <p className="text-xs text-muted-foreground">
                  Expires {new Date(device.expires_at).toLocaleTimeString()}
                </p>
              }
            />
            <Button size="sm" onClick={() => onReview(device)}>
              Review
            </Button>
          </div>
        ))}
      </div>
    </section>
  )
}
