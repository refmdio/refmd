/**
 * Recovery Page
 *
 * Allows users to recover their account using the 24-word BIP39 mnemonic.
 * This is used when the user has lost access to all their devices
 * and needs to restore their UMK (User Master Key).
 *
 * Recovery Flow:
 * 1. User enters email + 24-word mnemonic + password
 * 2. Fetch recovery data (recovery-encrypted UMK, identity keys)
 * 3. Derive RUK from mnemonic, decrypt UMK
 * 4. Decrypt identity keys with UMK
 * 5. Login with email/password
 * 6. Generate new device keys
 * 7. Create pending device and self-approve using recovered identity keys
 * 8. Store device keys and complete authentication
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState, useRef, useEffect, useCallback } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import {
  isValidMnemonic,
  deriveRukFromMnemonic,
  unwrapUmkWithRuk,
  decryptIdentityPrivateKeys,
  generateDeviceKeyPair,
  sign,
  deriveAuthKeys,
  generateDsk,
  storeDsk,
  wrapAndStoreDeviceKeys,
  wrapAndStoreUmk,
  storeDeviceId,
  base64UrlDecode,
  base64UrlEncode,
  generateSasEmojis,
} from '@/shared/lib/crypto'
import type { IdentityKeyPair, DeviceKeyPair } from '@/shared/lib/crypto'
import { SasVerification } from '@/features/device/ui/SasVerification'
import { authApi, deviceApi, ApiRequestError, sseUrls } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import { setPopCredentials } from '@/shared/lib/pop-store'

export const Route = createFileRoute('/auth/recovery')({
  component: RecoveryPage,
})

type RecoveryStep = 'input' | 'recovering' | 'waiting-for-approval' | 'success' | 'error'

function RecoveryPage() {
  const navigate = useNavigate()
  const { setAuthState, setDeviceState } = useAuthContext()
  const [step, setStep] = useState<RecoveryStep>('input')
  const [words, setWords] = useState<string[]>(Array(24).fill(''))
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [statusMessage, setStatusMessage] = useState('')
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])
  const eventSourceRef = useRef<EventSource | null>(null)

  // State for waiting-for-approval step
  const [pendingDeviceId, setPendingDeviceId] = useState<string | null>(null)
  const [sasEmojis, setSasEmojis] = useState<string | null>(null)
  const [recoveredUmk, setRecoveredUmk] = useState<Uint8Array | null>(null)
  const [recoveredIdentityKeys, setRecoveredIdentityKeys] = useState<IdentityKeyPair | null>(null)
  const [deviceKeyPair, setDeviceKeyPair] = useState<DeviceKeyPair | null>(null)
  const [pendingUserId, setPendingUserId] = useState<string | null>(null)
  const [pendingEmail, setPendingEmail] = useState<string | null>(null)
  const [pendingExpiresAt, setPendingExpiresAt] = useState<Date | null>(null)

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus()
  }, [])

  // Handle approval callback for SSE
  const handleApproval = useCallback(async (deviceId: string) => {
    if (!deviceKeyPair || !recoveredUmk || !recoveredIdentityKeys || !pendingUserId || !pendingEmail || !pendingExpiresAt) {
      setError('Missing recovery state')
      setStep('error')
      return
    }

    try {
      // Step 1: Set PoP credentials FIRST (synchronously) so API calls work
      setPopCredentials(deviceId, deviceKeyPair.signingPrivateKey)

      // Step 2: Generate and store DSK
      const dsk = await generateDsk()
      await storeDsk(dsk)

      // Step 3: Store device keys
      await wrapAndStoreDeviceKeys(deviceKeyPair, dsk, pendingUserId)
      await storeDeviceId(deviceId)

      // Step 4: Store UMK (we already have it from recovery)
      await wrapAndStoreUmk(recoveredUmk, dsk, pendingUserId)

      // Step 5: Set full auth state
      setAuthState({
        userId: pendingUserId,
        email: pendingEmail,
        expiresAt: pendingExpiresAt,
        umk: recoveredUmk,
        identityKeys: recoveredIdentityKeys,
      })

      // Step 6: Set device state
      setDeviceState({
        deviceId,
        deviceKeys: deviceKeyPair,
      })

      setStep('success')
      setStatusMessage('Recovery complete!')

      // Navigate to main app
      setTimeout(() => {
        navigate({ to: '/' })
      }, 1500)
    } catch (err) {
      console.error('Failed to complete device approval:', err)
      setError(err instanceof Error ? err.message : 'Failed to complete device setup')
      setStep('error')
    }
  }, [deviceKeyPair, recoveredUmk, recoveredIdentityKeys, pendingUserId, pendingEmail, pendingExpiresAt, navigate, setAuthState, setDeviceState])

  // SSE for approval status when waiting
  useEffect(() => {
    if (step !== 'waiting-for-approval' || !pendingDeviceId) {
      return
    }

    // Connect to SSE endpoint for this pending device
    const eventSource = new EventSource(
      sseUrls.pendingDeviceEvents(pendingDeviceId),
      { withCredentials: true }
    )
    eventSourceRef.current = eventSource

    eventSource.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data)

        if (data.type === 'pending_approved' && data.pending_id === pendingDeviceId) {
          eventSource.close()
          eventSourceRef.current = null

          if (data.device_id) {
            await handleApproval(data.device_id)
          }
        } else if (data.type === 'pending_removed' && data.pending_id === pendingDeviceId) {
          eventSource.close()
          eventSourceRef.current = null
          setError('Registration was rejected or expired. Please try again.')
          setStep('error')
        }
      } catch (err) {
        console.error('Failed to parse SSE event:', err)
      }
    }

    eventSource.onerror = (err) => {
      console.error('SSE connection error:', err)
    }

    return () => {
      eventSource.close()
      eventSourceRef.current = null
    }
  }, [step, pendingDeviceId, handleApproval])

  const handleWordChange = (index: number, value: string) => {
    const newWords = [...words]

    // Handle paste of full mnemonic
    if (value.includes(' ') && index === 0) {
      const pastedWords = value.trim().toLowerCase().split(/\s+/)
      if (pastedWords.length === 24) {
        setWords(pastedWords)
        inputRefs.current[23]?.focus()
        return
      }
    }

    newWords[index] = value.toLowerCase().trim()
    setWords(newWords)

    // Auto-advance to next input
    if (value && index < 23) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    // Navigate with arrow keys
    if (e.key === 'ArrowRight' && index < 23) {
      inputRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      const newIndex = index - 4
      if (newIndex >= 0) inputRefs.current[newIndex]?.focus()
    } else if (e.key === 'ArrowDown') {
      const newIndex = index + 4
      if (newIndex < 24) inputRefs.current[newIndex]?.focus()
    } else if (e.key === 'Backspace' && !words[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    const mnemonic = words.join(' ')

    // Validate inputs
    if (!email.trim()) {
      setError('Please enter your email address.')
      return
    }

    if (!password) {
      setError('Please enter your password.')
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
      const identityKeys = decryptIdentityPrivateKeys(
        {
          encryptedEcdhPrivate: base64UrlDecode(recoveryData.encrypted_ecdh_private),
          ecdhPrivateNonce: base64UrlDecode(recoveryData.encrypted_ecdh_private_nonce),
          encryptedSigningPrivate: base64UrlDecode(recoveryData.encrypted_signing_private),
          signingPrivateNonce: base64UrlDecode(recoveryData.encrypted_signing_private_nonce),
        },
        umk,
        recoveryData.user_id
      )

      // Step 5: Get salt and derive auth keys
      setStatusMessage('Deriving password key…')
      const saltData = await authApi.getSalt(email.trim())
      const derivedKeys = await deriveAuthKeys(password, saltData.salt, {
        memory_cost: saltData.kdf_params.memory_cost,
        time_cost: saltData.kdf_params.time_cost,
        parallelism: saltData.kdf_params.parallelism,
      })

      // Step 6: Login
      setStatusMessage('Logging in…')
      const loginResponse = await authApi.login({
        email: email.trim(),
        auth_key: derivedKeys.authKeyBase64,
        remember_me: false,
      })

      // Step 7: Generate new device keys
      setStatusMessage('Setting up new device…')
      const newDeviceKeyPair = generateDeviceKeyPair()

      // Build the message to sign: device_signing_pk || device_ecdh_pk || client_nonce
      const clientNonce = crypto.getRandomValues(new Uint8Array(16))
      const message = new Uint8Array(32 + 32 + 16)
      message.set(newDeviceKeyPair.signingPublicKey, 0)
      message.set(newDeviceKeyPair.ecdhPublicKey, 32)
      message.set(clientNonce, 64)

      // Sign device keys with recovered identity signing key
      const identitySignature = sign(message, identityKeys.signingPrivate)

      // Step 8: Create pending device
      setStatusMessage('Registering device…')
      const deviceName = `Recovered Device - ${navigator.userAgent.split(' ')[0]}`

      const pendingDevice = await deviceApi.createPendingDevice({
        device_name: deviceName,
        device_type: 'browser',
        ecdh_public_key: base64UrlEncode(newDeviceKeyPair.ecdhPublicKey),
        signing_public_key: base64UrlEncode(newDeviceKeyPair.signingPublicKey),
        client_nonce: base64UrlEncode(clientNonce),
      })

      // Step 9: Check if user has existing devices
      if (loginResponse.has_devices) {
        // User has existing devices - wait for approval from existing device
        // This ensures KEK distribution happens via PendingDeviceDialog
        setStatusMessage('Waiting for approval from existing device…')

        // Calculate SAS emojis
        const sasEmojisStr = generateSasEmojis(
          identityKeys.signingPublic,
          newDeviceKeyPair.signingPublicKey,
          newDeviceKeyPair.ecdhPublicKey,
          clientNonce
        )

        // Store state for SSE handler
        setPendingDeviceId(pendingDevice.id)
        setSasEmojis(sasEmojisStr)
        setRecoveredUmk(umk)
        setRecoveredIdentityKeys(identityKeys)
        setDeviceKeyPair(newDeviceKeyPair)
        setPendingUserId(loginResponse.user_id)
        setPendingEmail(loginResponse.email)
        setPendingExpiresAt(new Date(loginResponse.expires_at))

        // Switch to waiting-for-approval step
        setStep('waiting-for-approval')
        return
      }

      // No existing devices - self-approve using recovered identity keys
      setStatusMessage('Approving device…')
      const approvalResponse = await deviceApi.approveDevice(pendingDevice.id, {
        identity_signature: base64UrlEncode(identitySignature),
      })

      // Step 10: Store device keys using DSK
      setStatusMessage('Saving device keys…')
      const dsk = await generateDsk()
      await storeDsk(dsk)
      await wrapAndStoreDeviceKeys(newDeviceKeyPair, dsk, loginResponse.user_id)
      await storeDeviceId(approvalResponse.id)
      await wrapAndStoreUmk(umk, dsk, loginResponse.user_id)

      // Set PoP credentials for future API calls
      setPopCredentials(approvalResponse.id, newDeviceKeyPair.signingPrivateKey)

      // Step 11: Set auth state
      setAuthState({
        userId: loginResponse.user_id,
        email: loginResponse.email,
        expiresAt: new Date(loginResponse.expires_at),
        umk,
        identityKeys,
      })

      // Set device state
      setDeviceState({
        deviceId: approvalResponse.id,
        deviceKeys: newDeviceKeyPair,
      })

      setStep('success')
      setStatusMessage('Recovery complete!')

      // Navigate to main app
      setTimeout(() => {
        navigate({ to: '/' })
      }, 1500)
    } catch (err) {
      console.error('Recovery error:', err)
      setStep('error')
      if (err instanceof ApiRequestError) {
        if (err.status === 404) {
          setError('Account not found. Please check your email address.')
        } else if (err.status === 401) {
          setError('Invalid password. Please check your password and try again.')
        } else {
          setError(err.message)
        }
      } else if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Recovery failed. Please try again.')
      }
    }
  }, [words, email, password, navigate, setAuthState, setDeviceState])

  const handleClear = () => {
    setWords(Array(24).fill(''))
    setEmail('')
    setPassword('')
    setError(null)
    setStep('input')
    inputRefs.current[0]?.focus()
  }

  const handleRetry = () => {
    setStep('input')
    setError(null)
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold">Account Recovery</CardTitle>
          <CardDescription>
            Restore access to your account using your 24-word recovery phrase
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === 'recovering' && (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary" />
              <p className="text-muted-foreground">{statusMessage}</p>
            </div>
          )}

          {step === 'waiting-for-approval' && sasEmojis && (
            <div className="space-y-6">
              <div className="text-center">
                <p className="text-muted-foreground">
                  You have existing devices on this account. Please approve this device from one of your existing devices.
                </p>
              </div>

              <SasVerification emojis={sasEmojis} role="new" />

              <div className="text-center text-sm text-muted-foreground">
                <p>Open RefMD on your existing device and approve this device.</p>
                <p className="mt-2">The emojis must match exactly.</p>
              </div>

              <Button
                variant="outline"
                className="w-full"
                onClick={() => {
                  // Cancel pending device
                  if (pendingDeviceId) {
                    deviceApi.rejectPendingDevice(pendingDeviceId).catch(() => {})
                  }
                  if (eventSourceRef.current) {
                    eventSourceRef.current.close()
                    eventSourceRef.current = null
                  }
                  // Reset state
                  setPendingDeviceId(null)
                  setSasEmojis(null)
                  setRecoveredUmk(null)
                  setRecoveredIdentityKeys(null)
                  setDeviceKeyPair(null)
                  setPendingUserId(null)
                  setPendingEmail(null)
                  setPendingExpiresAt(null)
                  setStep('input')
                }}
              >
                Cancel
              </Button>
            </div>
          )}

          {step === 'success' && (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <div className="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
                <svg
                  className="h-6 w-6 text-green-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
              <p className="text-lg font-medium">Recovery Successful!</p>
              <p className="text-muted-foreground">Redirecting to your workspace…</p>
            </div>
          )}

          {(step === 'input' || step === 'error') && (
            <form onSubmit={handleSubmit} className="space-y-6">
              {error && (
                <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                  {error}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="your@email.com"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Your password"
                />
                <p className="text-xs text-muted-foreground">
                  Your password is still required to verify your identity.
                </p>
              </div>

              <div className="space-y-2">
                <Label>Recovery Phrase</Label>
                <p className="text-xs text-muted-foreground mb-4">
                  Enter each word in order. You can paste the full 24-word phrase into the first
                  field.
                </p>

                <div className="grid grid-cols-4 gap-2">
                  {words.map((word, index) => (
                    <div key={index} className="flex items-center gap-1">
                      <span className="text-xs text-muted-foreground w-5 text-right">
                        {index + 1}.
                      </span>
                      <Input
                        ref={(el) => {
                          inputRefs.current[index] = el
                        }}
                        type="text"
                        value={word}
                        onChange={(e) => handleWordChange(index, e.target.value)}
                        onKeyDown={(e) => handleKeyDown(index, e)}
                        placeholder="word"
                        className="h-8 text-sm font-mono"
                        autoComplete="off"
                        autoCorrect="off"
                        autoCapitalize="off"
                        spellCheck={false}
                      />
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex gap-2">
                <Button type="submit" className="flex-1">
                  Recover Account
                </Button>
                {step === 'error' ? (
                  <Button type="button" variant="outline" onClick={handleRetry}>
                    Try Again
                  </Button>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleClear}
                  >
                    Clear
                  </Button>
                )}
              </div>

              <div className="text-center">
                <Button
                  type="button"
                  variant="link"
                  onClick={() => navigate({ to: '/auth/login' })}
                >
                  Back to Login
                </Button>
              </div>
            </form>
          )}

          <div className="mt-6 p-4 bg-muted rounded-lg">
            <h4 className="font-semibold text-sm mb-2">Important Security Notes</h4>
            <ul className="text-xs text-muted-foreground space-y-1">
              <li>Never share your recovery phrase with anyone</li>
              <li>RefMD staff will never ask for your recovery phrase</li>
              <li>Make sure you&apos;re on the official RefMD website</li>
              <li>Your recovery phrase proves you own the account</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </main>
  )
}
