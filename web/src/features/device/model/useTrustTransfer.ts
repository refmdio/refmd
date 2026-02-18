/**
 * Trust Transfer Hook
 *
 * Manages dialog state for trust state transfer during device registration.
 * Decision logic is delegated to trust-transfer-service (pure functions);
 * this hook only applies the resulting actions to React state.
 *
 * Flow:
 *   executeTrustTransfer
 *     ├─ Phase 1: Request transfer nonce
 *     ├─ Phase 2: Retrieve encrypted trust state
 *     ├─ Phase 3: Verify all devices TOFU
 *     │    └─ key changes? → deviceKeyChange dialog → onQueueEmpty → applySenderAction
 *     └─ Phase 4: applySenderAction
 *          ├─ skip → done
 *          ├─ abort → error
 *          ├─ show_key_change → senderKeyChange dialog → afterTrust → safeImportTrustState
 *          └─ import → safeImportTrustState
 */

import { useReducer, useCallback } from 'react'
import { logger } from '@/shared/lib/logger'
import { useKeyChangeFlow, useLatest } from '@/shared/hooks'
import {
  safeImportTrustState,
  verifySenderAndResolve,
  buildDirectImportAction,
  TrustTransferAbortError,
  fetchTrustData,
  type TrustDeviceInfo,
  type TrustStateResponse,
  type ImportParams,
  type SenderAction,
} from '../lib/trust-transfer-service'

// --- Result handling helper ---

/**
 * Route a TrustTransferResult to either complete or error callbacks.
 * @internal Exported for testing
 */
export function handleNonPendingResult(
  result: TrustTransferResult,
  dispatch: React.Dispatch<PendingAction>,
  onComplete: () => void,
  onError: (message: string) => void,
): void {
  dispatch({ type: 'RESET' })
  if (result.status === 'security_abort') {
    onError(result.message)
  } else {
    onComplete()
  }
}

// --- State machine ---

export type PendingState =
  | { phase: 'idle' }
  | { phase: 'device_key_change'; devices: TrustDeviceInfo[]; stateResponse: TrustStateResponse; transferNonce: Uint8Array; deviceId: string; ecdhPrivateKey: Uint8Array; userId: string }
  | { phase: 'sender_key_change'; senderDeviceId: string; importParams: ImportParams }

export type PendingAction =
  | { type: 'ENTER_DEVICE_KEY_CHANGE'; devices: TrustDeviceInfo[]; stateResponse: TrustStateResponse; transferNonce: Uint8Array; deviceId: string; ecdhPrivateKey: Uint8Array; userId: string }
  | { type: 'ENTER_SENDER_KEY_CHANGE'; senderDeviceId: string; importParams: ImportParams }
  | { type: 'RESET' }

/** @internal Exported for testing */
export function pendingReducer(_state: PendingState, action: PendingAction): PendingState {
  switch (action.type) {
    case 'ENTER_DEVICE_KEY_CHANGE':
      return {
        phase: 'device_key_change',
        devices: action.devices,
        stateResponse: action.stateResponse,
        transferNonce: action.transferNonce,
        deviceId: action.deviceId,
        ecdhPrivateKey: action.ecdhPrivateKey,
        userId: action.userId,
      }
    case 'ENTER_SENDER_KEY_CHANGE':
      return { phase: 'sender_key_change', senderDeviceId: action.senderDeviceId, importParams: action.importParams }
    case 'RESET':
      return { phase: 'idle' }
  }
}

// --- Exported types ---

export type TrustTransferResult =
  | { status: 'success' }
  | { status: 'skipped'; reason: string }
  | { status: 'pending' }
  | { status: 'retryable_error'; message: string }
  | { status: 'security_abort'; message: string }

export interface UseTrustTransferReturn {
  executeTrustTransfer: (params: { deviceId: string; ecdhPrivateKey: Uint8Array; userId: string }) => Promise<TrustTransferResult>
  senderKeyChangeDialogProps: import('@/shared/hooks').KeyChangeWarningDialogProps | null
  deviceKeyChangeDialogProps: import('@/shared/hooks').KeyChangeWarningDialogProps | null
}

/**
 * Hook for trust state transfer during device registration.
 * Applies SenderAction results to dialog state — decision logic lives in the service layer.
 */
export function useTrustTransfer(
  onComplete: () => void,
  onError: (message: string) => void
): UseTrustTransferReturn {
  const [pending, dispatch] = useReducer(pendingReducer, { phase: 'idle' })

  const clearAndComplete = useCallback(() => {
    dispatch({ type: 'RESET' })
    onComplete()
  }, [onComplete])

  const onCompleteRef = useLatest(onComplete)
  const onErrorRef = useLatest(onError)
  const pendingRef = useLatest(pending)

  // --- Apply a pure SenderAction to React state ---

  const applySenderAction = useCallback(async (senderAction: SenderAction): Promise<TrustTransferResult> => {
    switch (senderAction.action) {
      case 'skip':
        return { status: 'skipped', reason: senderAction.reason }
      case 'abort':
        return { status: 'security_abort', message: senderAction.message }
      case 'show_key_change':
        dispatch({ type: 'ENTER_SENDER_KEY_CHANGE', senderDeviceId: senderAction.senderDeviceId, importParams: senderAction.importParams })
        senderPushRef.current(senderAction.keyChangeItem)
        return { status: 'pending' }
      case 'import': {
        const importError = await safeImportTrustState(senderAction.importParams, senderAction.senderDeviceId)
        if (importError) return { status: 'retryable_error', message: importError }
        return { status: 'success' }
      }
    }
  }, [])

  // --- Dialog flows ---

  const senderKeyChange = useKeyChangeFlow({
    afterTrust: async () => {
      const p = pendingRef.current
      if (p.phase !== 'sender_key_change') return
      const importError = await safeImportTrustState(p.importParams, p.senderDeviceId)
      if (importError) {
        dispatch({ type: 'RESET' })
        onErrorRef.current(importError)
        return
      }
      clearAndComplete()
    },
    onBlock: clearAndComplete,
    onCancel: clearAndComplete,
  })

  const senderPushRef = useLatest(senderKeyChange.push)

  /** Handle device key change queue completion: verify sender and apply result */
  const handleDeviceKeyChangeResolved = useCallback(async () => {
    const p = pendingRef.current
    if (p.phase !== 'device_key_change') return
    const { devices, stateResponse, transferNonce, deviceId, ecdhPrivateKey, userId } = p

    const senderAction = await verifySenderAndResolve(devices, stateResponse, transferNonce, userId, deviceId, ecdhPrivateKey)
    const result = await applySenderAction(senderAction)

    if (result.status !== 'pending') {
      handleNonPendingResult(result, dispatch, onCompleteRef.current, onErrorRef.current)
    }
  }, [pendingRef, applySenderAction, onCompleteRef, onErrorRef])

  const deviceKeyChange = useKeyChangeFlow({
    onQueueEmpty: handleDeviceKeyChangeResolved,
    onBlock: clearAndComplete,
    onCancel: clearAndComplete,
  })

  // --- Main entry point ---

  const executeTrustTransfer = useCallback(async (
    params: { deviceId: string; ecdhPrivateKey: Uint8Array; userId: string }
  ): Promise<TrustTransferResult> => {
    try {
      const data = await fetchTrustData(params)
      if (!data) return { status: 'skipped', reason: 'No trust state available' }

      const { transferNonce, stateResponse, devicesWithKeyChange, deviceKeyInfos } = data

      if (devicesWithKeyChange.length > 0) {
        deviceKeyChange.set(devicesWithKeyChange)
        dispatch({
          type: 'ENTER_DEVICE_KEY_CHANGE',
          devices: deviceKeyInfos, stateResponse, transferNonce,
          deviceId: params.deviceId, ecdhPrivateKey: params.ecdhPrivateKey, userId: params.userId,
        })
        return { status: 'pending' }
      }

      const senderAction = buildDirectImportAction(
        deviceKeyInfos, stateResponse, transferNonce, params.userId, params.deviceId, params.ecdhPrivateKey
      )
      return await applySenderAction(senderAction)
    } catch (err) {
      if (err instanceof TrustTransferAbortError) {
        return { status: 'security_abort', message: err.message }
      }
      const message = err instanceof Error ? err.message : 'Trust transfer failed'
      logger.warn('trust-transfer', message)
      return { status: 'retryable_error', message }
    }
  }, [deviceKeyChange.set, applySenderAction])

  return {
    executeTrustTransfer,
    senderKeyChangeDialogProps: senderKeyChange.dialogProps,
    deviceKeyChangeDialogProps: deviceKeyChange.dialogProps,
  }
}
