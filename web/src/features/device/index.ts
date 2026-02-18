/**
 * Device Feature
 *
 * Multi-device support for E2EE key distribution
 */

export { useDevice } from './model/useDevice'
export { PendingDeviceProvider } from './ui/PendingDeviceMonitor'
export { usePendingDevices } from './model/usePendingDevices'
export { SasVerification } from './ui/SasVerification'
export { useTrustTransfer } from './model/useTrustTransfer'
export { useDeviceRevocation } from './model/useDeviceRevocation'
export { useDeviceApprovalSSE } from './model/useDeviceApprovalSSE'
export { useDeviceRegistrationApproval } from './model/useDeviceRegistrationApproval'
export { useTofuVerification } from './model/useTofuVerification'
export { silentRejectDevice } from './model/useDeviceApprovalFlow'
export { selfApproveDevice } from './lib/self-approve-device-service'
export { findApprovedDeviceBySigningKey } from './lib/device-registration-service'
