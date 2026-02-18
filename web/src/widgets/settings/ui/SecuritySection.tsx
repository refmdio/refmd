/**
 * Security Section
 *
 * Trusted devices management orchestrator.
 */

import { Spinner } from '@/shared/ui/spinner'
import { KeyChangeGuard } from '@/shared/ui/KeyChangeGuard'
import { useSecuritySection } from '../model/useSecuritySection'
import { PendingDevicesSection } from './PendingDevicesSection'
import { TrustedDevicesList } from './TrustedDevicesList'
import { RevokeDeviceDialog } from './RevokeDeviceDialog'

interface SecuritySectionProps {
  onClose: () => void
}

export function SecuritySection({ onClose }: SecuritySectionProps) {
  const {
    pendingDevices,
    tofu,
    revocation,
    revokeTargetId,
    revokeTargetDevice,
    setRevokeTargetId,
    confirmRevoke,
    reviewPending,
  } = useSecuritySection(onClose)

  return (
    <KeyChangeGuard dialogProps={revocation.keyChangeDialogProps ?? tofu.keyChangeDialogProps}>
    <div className="p-6 space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1">Security</h3>
        <p className="text-sm text-muted-foreground">
          Manage your trusted devices and security settings.
        </p>
      </div>

      <PendingDevicesSection devices={pendingDevices} onReview={reviewPending} />

      {revocation.rotatingKek && (
        <div className="flex items-center gap-3 p-3 rounded border border-blue-500/30 bg-blue-500/5">
          <Spinner size="sm" className="border-blue-500" />
          <span className="text-sm text-blue-600">Rotating encryption keys...</span>
        </div>
      )}

      <TrustedDevicesList
        devices={tofu.devices}
        loading={tofu.loading}
        error={tofu.error}
        compromisedDevices={tofu.compromisedDevices}
        devicesWithKeyChange={tofu.devicesWithKeyChange}
        rotatingKek={revocation.rotatingKek}
        onRevokeRequest={setRevokeTargetId}
      />

      <RevokeDeviceDialog
        deviceName={revokeTargetDevice?.name ?? null}
        open={revokeTargetId !== null}
        onClose={() => setRevokeTargetId(null)}
        onConfirm={confirmRevoke}
      />
    </div>
    </KeyChangeGuard>
  )
}
