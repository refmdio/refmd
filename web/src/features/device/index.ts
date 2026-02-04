/**
 * Device Feature
 *
 * Multi-device support for E2EE key distribution
 */

export { useDevice, type UseDeviceReturn, type DeviceRegistrationState, type DeviceRegistrationStep } from './useDevice'
export { PendingDeviceProvider, usePendingDevices } from './ui/PendingDeviceMonitor'
