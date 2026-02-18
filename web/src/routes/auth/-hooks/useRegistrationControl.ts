/**
 * Registration Control Hook
 *
 * Manages auto-start, cancel, and retry for device registration.
 * Extracted from useDeviceRegistration to separate orchestration concerns.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { silentRejectDevice } from '@/features/device'
import { logout as performLogout } from '@/features/auth'
import type { DeviceType } from '@/shared/lib/device'

interface UseRegistrationControlParams {
  step: string
  pendingDeviceId: string | null
  startRegistration: (name: string, type: DeviceType) => Promise<void>
  reset: () => void
  clearAuthState: () => void
  deviceName: string
  deviceType: DeviceType
}

export function useRegistrationControl({
  step,
  pendingDeviceId,
  startRegistration,
  reset,
  clearAuthState,
  deviceName,
  deviceType,
}: UseRegistrationControlParams) {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const hasStartedRef = useRef(false)

  const handleStartRegistration = useCallback(async () => {
    if (hasStartedRef.current || loading) return
    hasStartedRef.current = true
    setError(null)
    setLoading(true)

    try {
      await startRegistration(deviceName, deviceType)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start registration')
      hasStartedRef.current = false
    } finally {
      setLoading(false)
    }
  }, [deviceName, deviceType, startRegistration, loading])

  useEffect(() => {
    if (step === 'idle' && !hasStartedRef.current) {
      handleStartRegistration()
    }
  }, [step, handleStartRegistration])

  const handleCancel = useCallback(async () => {
    if (pendingDeviceId) {
      await silentRejectDevice(pendingDeviceId)
    }
    try {
      await performLogout()
    } catch {
      // Ignore logout errors
    }
    clearAuthState()
    reset()
    hasStartedRef.current = false
    navigate({ to: '/auth/login' })
  }, [pendingDeviceId, clearAuthState, reset, navigate])

  const handleRetry = useCallback(() => {
    setError(null)
    hasStartedRef.current = false
    reset()
  }, [reset])

  return { loading, error, setError, handleCancel, handleRetry }
}
