/**
 * Device Approval Flow Hook
 *
 * Orchestrates the full pending device approval process from an existing device.
 * Extracts all crypto logic from PendingDeviceDialog.
 *
 * Responsibilities:
 * 1. SAS data fetch + emoji calculation
 * 2. New device TOFU verification
 * 3. Approval signature + API call
 * 4. KEK distribution (all workspaces)
 * 5. UMK distribution (triggers SSE event)
 * 6. Trust State Transfer (SSE wait + encrypt + submit)
 * 7. Key change warning dialog management (via useKeyChangeFlow)
 */

import { useReducer, useCallback, useRef } from 'react'
import {
  base64UrlDecode,
  base64UrlEncode,
  generateSasEmojis,
  evaluateTofu,
  evaluateTofuWithoutPersist,
  dispatchTofuDecision,
  signDeviceApproval,
} from '@/shared/lib/crypto'
import { deviceApi, type PendingDevice } from '@/shared/api'
import { useKeyChangeFlow } from '@/shared/hooks'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'
import { approveAndDistributeKeys } from '../lib/device-approval-service'

// --- Types ---

type Step = 'loading' | 'verify' | 'approving' | 'error'

interface PendingDeviceKeys {
  signingPk: Uint8Array
  ecdhPk: Uint8Array
  clientNonce: Uint8Array
}

export interface ApprovalState {
  step: Step
  sasEmojis: string | null
  error: string | null
  pendingDeviceKeys: PendingDeviceKeys | null
}

export type ApprovalAction =
  | { type: 'START_LOADING' }
  | { type: 'SAS_READY'; sasEmojis: string; keys: PendingDeviceKeys }
  | { type: 'KEYS_FETCHED'; keys: PendingDeviceKeys }
  | { type: 'SHOW_VERIFY'; sasEmojis: string }
  | { type: 'START_APPROVING' }
  | { type: 'ERROR'; message: string }

/** @internal Exported for testing */
export function approvalReducer(state: ApprovalState, action: ApprovalAction): ApprovalState {
  switch (action.type) {
    case 'START_LOADING':
      return { ...state, step: 'loading', error: null }
    case 'SAS_READY':
      return { step: 'verify', sasEmojis: action.sasEmojis, error: null, pendingDeviceKeys: action.keys }
    case 'KEYS_FETCHED':
      return { ...state, pendingDeviceKeys: action.keys }
    case 'SHOW_VERIFY':
      return { ...state, step: 'verify', sasEmojis: action.sasEmojis }
    case 'START_APPROVING':
      return { ...state, step: 'approving', error: null }
    case 'ERROR':
      return { ...state, step: 'error', error: action.message }
  }
}

export const initialApprovalState: ApprovalState = {
  step: 'loading',
  sasEmojis: null,
  error: null,
  pendingDeviceKeys: null,
}

// --- Pure helpers (no React state) ---

function computeSasEmojis(identitySigningPk: Uint8Array, keys: PendingDeviceKeys): string {
  return generateSasEmojis(identitySigningPk, keys.signingPk, keys.ecdhPk, keys.clientNonce)
}

async function fetchSasData(deviceId: string): Promise<PendingDeviceKeys> {
  const sasResponse = await deviceApi.getSas(deviceId)
  return {
    signingPk: base64UrlDecode(sasResponse.device_signing_public_key),
    ecdhPk: base64UrlDecode(sasResponse.device_ecdh_public_key),
    clientNonce: base64UrlDecode(sasResponse.client_nonce),
  }
}

function buildApprovalSignature(
  keys: PendingDeviceKeys,
  signingPrivateKey: Uint8Array,
): Uint8Array {
  return signDeviceApproval({
    device_signing_public_key: base64UrlEncode(keys.signingPk),
    device_ecdh_public_key: base64UrlEncode(keys.ecdhPk),
    client_nonce: base64UrlEncode(keys.clientNonce),
  }, signingPrivateKey)
}

export async function silentRejectDevice(deviceId: string): Promise<void> {
  try {
    await deviceApi.rejectPendingDevice(deviceId)
  } catch {
    // Ignore errors - device may already be removed
  }
}

// --- Hook ---

interface UseDeviceApprovalFlowParams {
  device: PendingDevice
  auth: AuthState | null
  currentDevice: DeviceState | null
  onApproved: () => void
  onClose: () => void
}

export function useDeviceApprovalFlow({
  device,
  auth,
  currentDevice,
  onApproved,
  onClose,
}: UseDeviceApprovalFlowParams) {
  const [state, dispatch] = useReducer(approvalReducer, initialApprovalState)
  const cancelledRef = useRef(false)

  const keyChange = useKeyChangeFlow({
    afterTrust: async () => {
      if (state.pendingDeviceKeys && auth?.identityKeys) {
        dispatch({
          type: 'SHOW_VERIFY',
          sasEmojis: computeSasEmojis(auth.identityKeys.signingPublic, state.pendingDeviceKeys),
        })
      }
    },
    onBlock: async () => {
      await silentRejectDevice(device.id)
      onClose()
    },
    onCancel: () => {
      onClose()
    },
  })

  /** Phase 1: Fetch SAS data and run initial TOFU check */
  const loadSas = useCallback(async () => {
    if (!auth?.identityKeys || !auth?.userId) {
      dispatch({ type: 'ERROR', message: 'Identity keys not available' })
      return
    }

    try {
      dispatch({ type: 'START_LOADING' })

      const keys = await fetchSasData(device.id)
      if (cancelledRef.current) return

      const tofuDecision = await evaluateTofuWithoutPersist(
        auth.userId, device.id, keys.signingPk, keys.ecdhPk
      )

      dispatch({ type: 'KEYS_FETCHED', keys })

      if (dispatchTofuDecision(tofuDecision, device.name, {
        onAbort: (reason) => dispatch({ type: 'ERROR', message: reason }),
        onKeyChanged: (item) => keyChange.push(item),
      })) return

      dispatch({
        type: 'SAS_READY',
        sasEmojis: computeSasEmojis(auth.identityKeys.signingPublic, keys),
        keys,
      })
    } catch (err) {
      if (cancelledRef.current) return
      dispatch({ type: 'ERROR', message: err instanceof Error ? err.message : 'Failed to load SAS' })
    }
  }, [device.id, device.name, auth?.identityKeys, auth?.userId, keyChange.push])

  /** Phase 2: Re-verify TOFU, sign approval, and distribute keys */
  const handleApprove = useCallback(async () => {
    if (!auth?.identityKeys || !auth?.umk || !auth?.userId || !currentDevice || !state.pendingDeviceKeys) {
      dispatch({ type: 'ERROR', message: 'Missing required keys or device info' })
      return
    }

    const keys = state.pendingDeviceKeys

    try {
      dispatch({ type: 'START_APPROVING' })

      const tofuDecision = await evaluateTofu(
        auth.userId, device.id, keys.signingPk, keys.ecdhPk
      )

      if (dispatchTofuDecision(tofuDecision, device.name, {
        onAbort: (reason) => dispatch({ type: 'ERROR', message: reason }),
        onKeyChanged: (item) => { keyChange.push(item); dispatch({ type: 'SHOW_VERIFY', sasEmojis: state.sasEmojis! }) },
      })) return

      const signature = buildApprovalSignature(keys, auth.identityKeys.signingPrivate)

      const approveResponse = await deviceApi.approveDevice(device.id, {
        identity_signature: base64UrlEncode(signature),
      })

      await approveAndDistributeKeys({
        auth: auth as AuthState & { umk: Uint8Array },
        currentDevice,
        targetEcdhPk: keys.ecdhPk,
        approvedDeviceId: approveResponse.id,
      })

      onApproved()
    } catch (err) {
      dispatch({ type: 'ERROR', message: err instanceof Error ? err.message : 'Failed to approve device' })
    }
  }, [auth, currentDevice, state.pendingDeviceKeys, state.sasEmojis, device.id, device.name, onApproved, keyChange.push])

  const handleReject = useCallback(async () => {
    await silentRejectDevice(device.id)
    onClose()
  }, [device.id, onClose])

  return {
    step: state.step,
    sasEmojis: state.sasEmojis,
    error: state.error,
    loadSas,
    handleApprove,
    handleReject,
    cancelledRef,
    keyChangeDialogProps: keyChange.dialogProps,
  }
}
