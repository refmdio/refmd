/**
 * Recovery Flow Hook
 *
 * Orchestrates the full account recovery process using BIP39 mnemonic.
 * Extracts all crypto logic from the recovery route.
 *
 * Responsibilities:
 * - BIP39 validation + recovery file parsing
 * - Recovery data fetch → RUK derivation → UMK decryption
 * - Identity keys decryption
 * - Recovery session creation (challenge signing)
 * - Device key generation + self-approval
 * - Device state initialization
 * - Auth/Device state setup
 */

import { useCallback } from 'react'
import {
  isValidMnemonic,
  deriveRukFromMnemonic,
  unwrapUmkWithRuk,
  decryptIdentityKeysFromResponse,
  base64UrlDecode,
  base64UrlEncode,
  buildRecoverySessionMessage,
  sign,
  storeSessionUmk,
} from '@/shared/lib/crypto'
import { detectDeviceName, detectDeviceType, type DeviceType } from '@/shared/lib/device'
import { authApi, ApiError } from '@/shared/api'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'
import type { DeviceKeyPair } from '@/shared/lib/crypto'
import { buildAuthState, buildDeviceState } from '@/shared/model/session-hydration'

export type RecoveryStep = 'input' | 'recovering' | 'success' | 'error'

interface SelfApproveDeviceFn {
  (params: {
    userId: string
    identitySigningPrivateKey: Uint8Array
    umk: Uint8Array
    deviceName: string
    deviceType: DeviceType
  }): Promise<{ deviceId: string; deviceKeyPair: DeviceKeyPair }>
}

interface UseRecoveryFlowParams {
  selfApproveDevice: SelfApproveDeviceFn
  setFullSession: (auth: AuthState, device: DeviceState) => void
  setStep: (step: RecoveryStep) => void
  setStatusMessage: (msg: string) => void
  setError: (msg: string) => void
  onSuccess: () => void
}

export function useRecoveryFlow({
  selfApproveDevice,
  setFullSession,
  setStep,
  setStatusMessage,
  setError,
  onSuccess,
}: UseRecoveryFlowParams) {
  const handleSubmit = useCallback(async (email: string, words: string[]) => {
    const mnemonic = words.join(' ')

    if (!email.trim()) {
      setError('Please enter your email address.')
      return
    }

    if (!isValidMnemonic(mnemonic)) {
      setError('Invalid recovery phrase. Please check all 24 words.')
      return
    }

    setStep('recovering')

    try {
      // Step 1: Fetch recovery data
      setStatusMessage('Fetching recovery data…')
      const recoveryData = await authApi.getRecoveryData(email.trim())

      // Step 2: Derive RUK from mnemonic
      setStatusMessage('Deriving recovery key…')
      const ruk = await deriveRukFromMnemonic(mnemonic)

      // Step 3: Decrypt UMK with RUK
      setStatusMessage('Decrypting master key…')
      const recoveryEncryptedUmk = base64UrlDecode(recoveryData.recovery_encrypted_umk)
      const recoveryNonce = base64UrlDecode(recoveryData.recovery_nonce)

      let umk: Uint8Array
      try {
        umk = unwrapUmkWithRuk(
          { encryptedUmk: recoveryEncryptedUmk, nonce: recoveryNonce },
          ruk,
          recoveryData.user_id
        )
      } catch {
        throw new Error('Invalid recovery phrase. The mnemonic does not match this account.')
      }

      // Step 4: Decrypt identity keys with UMK
      setStatusMessage('Decrypting identity keys…')
      const identityKeys = decryptIdentityKeysFromResponse(recoveryData, umk, recoveryData.user_id)

      // Step 5: Get recovery challenge from server
      setStatusMessage('Getting recovery challenge…')
      const challengeResponse = await authApi.getRecoveryChallenge(email.trim())
      const challenge = base64UrlDecode(challengeResponse.challenge)

      // Step 6: Sign challenge with recovered identity key
      setStatusMessage('Signing challenge…')
      const timestamp = Math.floor(Date.now() / 1000)
      const signatureMessage = buildRecoverySessionMessage(challenge, email.trim(), timestamp)
      const identitySignatureForSession = sign(signatureMessage, identityKeys.signingPrivate)

      // Step 7: Create recovery session
      setStatusMessage('Creating session…')
      const sessionResponse = await authApi.createRecoverySession({
        email: email.trim(),
        challenge: challengeResponse.challenge,
        identity_signature: base64UrlEncode(identitySignatureForSession),
        timestamp,
      })

      // Step 8: Create + self-approve device (delegated to device service)
      setStatusMessage('Setting up new device…')
      const { deviceId, deviceKeyPair } = await selfApproveDevice({
        userId: sessionResponse.user_id,
        identitySigningPrivateKey: identityKeys.signingPrivate,
        umk,
        deviceName: `Recovered - ${detectDeviceName()}`,
        deviceType: detectDeviceType(),
      })

      // Step 9: Persist UMK to sessionStorage so hasResumableSession() works
      // even when DSK is unavailable (PDK fallback environment).
      // Recovery uses mnemonic (not password), so PDK wrapping is not possible.
      storeSessionUmk(umk, sessionResponse.user_id)

      // Step 10: Set full session (auth + device) atomically
      setFullSession(
        buildAuthState({
          userId: sessionResponse.user_id,
          email: sessionResponse.email,
          expiresAt: sessionResponse.expires_at,
          umk,
          identityKeys,
        }),
        buildDeviceState({ deviceId, deviceKeys: deviceKeyPair }),
      )

      setStep('success')
      setStatusMessage('Recovery complete!')
      onSuccess()
    } catch (err) {
      setStep('error')
      if (err instanceof ApiError) {
        if (err.status === 404) {
          setError('Account not found. Please check your email address.')
        } else if (err.status === 401) {
          setError('Invalid recovery phrase or challenge expired. Please try again.')
        } else {
          setError(err.message)
        }
      } else if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Recovery failed. Please try again.')
      }
    }
  }, [selfApproveDevice, setFullSession, setStep, setStatusMessage, setError, onSuccess])

  return { handleSubmit }
}
