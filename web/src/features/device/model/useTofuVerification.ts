/**
 * TOFU Verification Hook
 *
 * Handles device list loading with TOFU verification for each device.
 * Extracts crypto logic from SecuritySection widget.
 *
 * Responsibilities:
 * - Device list fetch + per-device TOFU verification loop
 * - Anti-rollback detection (revocation rollback)
 * - Key change warning queue management (via useKeyChangeFlow)
 * - Compromised device tracking
 * - Dialog handlers (trust/block/cancel)
 */

import { useState, useCallback } from 'react'
import { processDeviceListTofu } from '@/shared/lib/crypto'
import { isRevocationRolledBack } from '@/shared/lib/anti-rollback'
import { deviceApi } from '@/shared/api'
import { useKeyChangeFlow } from '@/shared/hooks'
import type { components } from '@/shared/api'

type Device = components['schemas']['DeviceResponse']

export function useTofuVerification(userId: string | undefined) {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [compromisedDevices, setCompromisedDevices] = useState<Set<string>>(new Set())
  const [devicesWithKeyChange, setDevicesWithKeyChange] = useState<Set<string>>(new Set())

  const keyChange = useKeyChangeFlow({
    afterTrust: async (item) => {
      setDevicesWithKeyChange((prev) => new Set([...prev, item.tofuNewEntry.deviceId]))
    },
    onBlock: (item) => {
      setCompromisedDevices((prev) => new Set([...prev, item.tofuNewEntry.deviceId]))
    },
    onCancel: (remaining) => {
      setDevicesWithKeyChange((prev) => {
        const next = new Set(prev)
        for (const item of remaining) next.add(item.tofuNewEntry.deviceId)
        return next
      })
    },
  })

  const loadDevices = useCallback(async () => {
    if (!userId) return

    try {
      setLoading(true)
      setError(null)
      const response = await deviceApi.listDevices()

      const detectedCompromised = new Set<string>()

      // Anti-rollback: check if any device was previously revoked
      for (const device of response.devices) {
        if (await isRevocationRolledBack(userId, device.id)) {
          detectedCompromised.add(device.id)
        }
      }

      // Batch TOFU verification
      const result = await processDeviceListTofu(response.devices, userId, {
        onAborted: (device) => {
          detectedCompromised.add(device.id)
          setCompromisedDevices(detectedCompromised)
          setDevices(response.devices)
          setError(`Security alert: Device "${device.name}" has a key mismatch. This may indicate tampering. Consider revoking this device immediately.`)
          setLoading(false)
        },
        onFailed: (failedDevices, failedIds) => {
          for (const id of failedIds) detectedCompromised.add(id)
          setCompromisedDevices(detectedCompromised)
          const names = failedDevices.map(d => d.name).join(', ')
          setError(`TOFU verification failed for device(s): ${names}. These devices may have corrupted keys.`)
        },
        onKeyChange: (items) => keyChange.set(items),
      })
      if (result.aborted) return

      // Reflect anti-rollback detections even when TOFU passed normally
      if (detectedCompromised.size > 0) {
        setCompromisedDevices(detectedCompromised)
      }

      setDevices(response.devices)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load devices')
    } finally {
      setLoading(false)
    }
  }, [userId, keyChange.set])

  return {
    devices,
    loading,
    error,
    setError,
    compromisedDevices,
    devicesWithKeyChange,
    loadDevices,
    keyChangeDialogProps: keyChange.dialogProps,
  }
}
