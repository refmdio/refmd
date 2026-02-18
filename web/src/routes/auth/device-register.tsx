/**
 * Device Registration Page
 *
 * Used when a user logs in on a new device that needs to be registered
 * to receive the UMK (User Master Key) from an existing device.
 * Uses SSE for real-time approval notifications.
 */

import { createFileRoute } from '@tanstack/react-router'
import {
  KeyChangeWarningPage,
  RegistrationLoadingState,
  RegistrationWaitingState,
  RegistrationErrorState,
} from './-components/RegistrationStates'
import { useDeviceRegistration } from './-hooks/useDeviceRegistration'

export const Route = createFileRoute('/auth/device-register')({
  component: DeviceRegisterPage,
})

function DeviceRegisterPage() {
  const {
    state,
    deviceName,
    sasEmojis,
    loading,
    displayError,
    keyChangeProps,
    handleRetry,
    handleCancel,
  } = useDeviceRegistration()

  if (keyChangeProps) {
    return <KeyChangeWarningPage {...keyChangeProps} />
  }

  if (state.step === 'idle' || state.step === 'generating-keys' || state.step === 'creating-pending' || loading) {
    return (
      <RegistrationLoadingState
        deviceName={deviceName}
        error={displayError}
        onRetry={handleRetry}
        onCancel={handleCancel}
      />
    )
  }

  if (state.step === 'waiting-for-approval') {
    return (
      <RegistrationWaitingState
        sasEmojis={sasEmojis}
        error={displayError}
        onRetry={handleRetry}
        onCancel={handleCancel}
      />
    )
  }

  if (state.step === 'error') {
    return (
      <RegistrationErrorState
        error={displayError!}
        onRetry={handleRetry}
        onCancel={handleCancel}
      />
    )
  }

  return null
}
