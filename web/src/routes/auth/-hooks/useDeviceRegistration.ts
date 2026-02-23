/**
 * Device Registration Orchestrator
 *
 * Wires together sub-hooks for device registration:
 * - useDevice: registration state machine
 * - useRegistrationControl: auto-start, cancel, retry
 * - useDeviceRegistrationApproval: post-approval crypto flow
 * - useTrustTransfer: trust state transfer
 * - useDeviceApprovalSSE: real-time approval notifications
 */

import { useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useDevice, useDeviceApprovalSSE, useTrustTransfer, useDeviceRegistrationApproval, findApprovedDeviceBySigningKey } from '@/features/device'
import { useAuthContext } from '@/shared/context'
import { WORKSPACE_STORAGE_KEY } from '@/entities/workspace'
import { detectDeviceType, detectDeviceName } from '@/shared/lib/device'
import type { KeyChangeWarningDialogProps } from '@/shared/model/key-change-types'
import { useRegistrationControl } from './useRegistrationControl'

function resolveKeyChangeDialogProps(
  sources: (KeyChangeWarningDialogProps | null | undefined)[]
): KeyChangeWarningDialogProps | null {
  for (const props of sources) {
    if (props) return props
  }
  return null
}

export function useDeviceRegistration(redirect?: string) {
  const navigate = useNavigate()
  const { auth, setFullSession, clearAuthState } = useAuthContext()
  const { state, startRegistration, reset } = useDevice()

  const deviceName = detectDeviceName()
  const deviceType = detectDeviceType()

  // Registration lifecycle control (auto-start, cancel, retry)
  const control = useRegistrationControl({
    step: state.step,
    pendingDeviceId: state.pendingDeviceId,
    startRegistration,
    reset,
    clearAuthState,
    deviceName,
    deviceType,
  })

  // Trust transfer — navigate to the redirect target, persisted workspace, or root
  const navigateToWorkspace = useCallback(() => {
    if (redirect) {
      navigate({ to: redirect })
    } else {
      const workspaceId = localStorage.getItem(WORKSPACE_STORAGE_KEY)
      if (workspaceId) {
        navigate({ to: '/workspace/$workspaceId', params: { workspaceId } })
      } else {
        navigate({ to: '/workspace' })
      }
    }
  }, [navigate, redirect])
  const trustTransfer = useTrustTransfer(navigateToWorkspace, control.setError)

  // Post-approval crypto flow
  const approval = useDeviceRegistrationApproval({
    auth,
    deviceState: state,
    setFullSession,
    executeTrustTransfer: trustTransfer.executeTrustTransfer,
    onNavigate: navigateToWorkspace,
    onError: control.setError,
  })

  // Verify whether the device was approved
  const verifyApproval = useCallback(async (): Promise<string | null> => {
    if (!state.deviceKeyPair) return null
    return findApprovedDeviceBySigningKey(state.deviceKeyPair.signingPublicKey)
  }, [state.deviceKeyPair])

  // SSE for real-time approval status
  useDeviceApprovalSSE({
    pendingDeviceId: state.pendingDeviceId,
    enabled: state.step === 'waiting-for-approval',
    onApproved: approval.handleApproval,
    onRejected: useCallback(() => {
      control.setError('Registration was rejected. Please try again.')
      reset()
    }, [reset, control.setError]),
    onExpired: useCallback(() => {
      control.setError('Registration expired. Please try again.')
      reset()
    }, [reset, control.setError]),
    verifyApproval,
  })

  const displayError = state.step === 'error' ? (state.error || control.error || 'Unknown error') : control.error
  const keyChangeProps = resolveKeyChangeDialogProps([
    trustTransfer.deviceKeyChangeDialogProps,
    trustTransfer.senderKeyChangeDialogProps,
    approval.keyChangeDialogProps,
  ])

  return {
    state,
    deviceName,
    sasEmojis: state.sasEmojis,
    loading: control.loading,
    displayError,
    keyChangeProps,
    handleRetry: control.handleRetry,
    handleCancel: control.handleCancel,
  }
}
