/**
 * Recovery Page
 *
 * Allows users to recover their account using the 24-word BIP39 mnemonic.
 * This is used when the user has lost access to all their devices
 * and needs to restore their UMK (User Master Key).
 *
 * Recovery Flow (no password required):
 * 1. User enters email + 24-word mnemonic
 * 2. Fetch recovery data (recovery-encrypted UMK, identity keys)
 * 3. Derive RUK from mnemonic, decrypt UMK
 * 4. Decrypt identity keys with UMK
 * 5. Get recovery challenge from server
 * 6. Sign challenge with recovered identity key
 * 7. Create recovery session (no password needed)
 * 8. Generate new device keys
 * 9. Create pending device and self-approve using recovered identity keys
 * 10. Store device keys and complete authentication
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
  generateDsk,
  storeDsk,
  wrapAndStoreDeviceKeys,
  wrapAndStoreUmk,
  storeDeviceId,
  base64UrlDecode,
  base64UrlEncode,
  buildRecoverySessionMessage,
  buildSignatureMessage,
  SIGNATURE_ACTION,
} from '@/shared/lib/crypto'
import { authApi, deviceApi, ApiRequestError } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import { setPopCredentials } from '@/shared/lib/pop-store'

export const Route = createFileRoute('/auth/recovery')({
  component: RecoveryPage,
})

type RecoveryStep = 'input' | 'recovering' | 'success' | 'error'

function RecoveryPage() {
  const navigate = useNavigate()
  const { setAuthState, setDeviceState } = useAuthContext()
  const [step, setStep] = useState<RecoveryStep>('input')
  const [words, setWords] = useState<string[]>(Array(24).fill(''))
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [statusMessage, setStatusMessage] = useState('')
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus()
  }, [])

  // Max file size (10KB should be more than enough for a recovery key file)
  const MAX_FILE_SIZE = 10 * 1024

  // Parse recovery key file content with strict validation
  const parseRecoveryFile = (content: string): { words: string[] } | { error: string } => {
    const lines = content.split('\n')

    // Check for RefMD header to ensure correct file type
    const hasHeader = lines.some(line => line.includes('RefMD Recovery Key'))
    if (!hasHeader) {
      return { error: 'File format not recognized. Please upload a RefMD recovery key file.' }
    }

    // Parse numbered lines strictly: require 1-24 in order
    const words: (string | null)[] = Array(24).fill(null)

    for (const line of lines) {
      // Match lines like " 1. word" or "1. word" or "01. word"
      const match = line.match(/^\s*(\d+)\.\s+([a-z]+)\s*$/i)
      if (match) {
        const num = parseInt(match[1], 10)
        const word = match[2].toLowerCase()

        // Validate number is in range 1-24
        if (num >= 1 && num <= 24) {
          // Check for duplicates
          if (words[num - 1] !== null) {
            return { error: `Duplicate entry for word ${num}.` }
          }
          words[num - 1] = word
        }
      }
    }

    // Check all 24 words are present
    const missingIndices = words
      .map((w, i) => w === null ? i + 1 : null)
      .filter((i): i is number => i !== null)

    if (missingIndices.length > 0) {
      if (missingIndices.length === 24) {
        return { error: 'No recovery words found in file.' }
      }
      return { error: `Missing word(s) at position: ${missingIndices.join(', ')}.` }
    }

    return { words: words as string[] }
  }

  // Handle file upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    // Check file size to prevent memory issues
    if (file.size > MAX_FILE_SIZE) {
      setError('File is too large. Recovery key files should be less than 10KB.')
      e.target.value = ''
      return
    }

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string
      const result = parseRecoveryFile(content)

      if ('error' in result) {
        setError(result.error)
        // Clear words on parse failure to avoid accidental submit with old data
        setWords(Array(24).fill(''))
        inputRefs.current[0]?.focus()
      } else {
        // Validate BIP39 mnemonic immediately
        const mnemonic = result.words.join(' ')
        if (!isValidMnemonic(mnemonic)) {
          setError('Invalid recovery key file: contains invalid BIP39 words.')
          setWords(Array(24).fill(''))
          inputRefs.current[0]?.focus()
        } else {
          setWords(result.words)
          setError(null)
          inputRefs.current[23]?.focus()
        }
      }
    }
    reader.onerror = () => {
      setError('Failed to read file.')
      setWords(Array(24).fill(''))
    }
    reader.readAsText(file)

    // Reset input so same file can be selected again
    e.target.value = ''
  }

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

      // Step 5: Get recovery challenge from server
      setStatusMessage('Getting recovery challenge…')
      const challengeResponse = await authApi.getRecoveryChallenge(email.trim())
      const challenge = base64UrlDecode(challengeResponse.challenge)

      // Step 6: Sign challenge with recovered identity key
      setStatusMessage('Signing challenge…')
      const timestamp = Math.floor(Date.now() / 1000)
      const signatureMessage = buildRecoverySessionMessage(challenge, email.trim(), timestamp)
      const identitySignatureForSession = sign(signatureMessage, identityKeys.signingPrivate)

      // Step 7: Create recovery session (no password required)
      setStatusMessage('Creating session…')
      const sessionResponse = await authApi.createRecoverySession({
        email: email.trim(),
        challenge: challengeResponse.challenge,
        identity_signature: base64UrlEncode(identitySignatureForSession),
        timestamp,
      })

      // Step 8: Generate new device keys
      setStatusMessage('Setting up new device…')
      const newDeviceKeyPair = generateDeviceKeyPair()

      // Build the JCS signature message for device approval
      const clientNonce = crypto.getRandomValues(new Uint8Array(16))
      const message = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_APPROVAL, {
        device_signing_public_key: base64UrlEncode(newDeviceKeyPair.signingPublicKey),
        device_ecdh_public_key: base64UrlEncode(newDeviceKeyPair.ecdhPublicKey),
        client_nonce: base64UrlEncode(clientNonce),
      })

      // Sign device keys with recovered identity signing key
      const identitySignature = sign(message, identityKeys.signingPrivate)

      // Step 9: Create pending device
      setStatusMessage('Registering device…')
      const deviceName = `Recovered Device - ${navigator.userAgent.split(' ')[0]}`

      const pendingDevice = await deviceApi.createPendingDevice({
        device_name: deviceName,
        device_type: 'browser',
        ecdh_public_key: base64UrlEncode(newDeviceKeyPair.ecdhPublicKey),
        signing_public_key: base64UrlEncode(newDeviceKeyPair.signingPublicKey),
        client_nonce: base64UrlEncode(clientNonce),
      })

      // Step 10: Self-approve using recovered identity keys
      // In recovery flow, we always self-approve because:
      // 1. User typically doesn't have access to existing devices (that's why they're recovering)
      // 2. Even if has_devices=true, waiting for existing device approval would leave user stuck
      // 3. KEKs will need to be distributed separately when user regains access to existing devices
      //    or when they are re-invited to workspaces
      setStatusMessage('Approving device…')
      const approvalResponse = await deviceApi.approveDevice(pendingDevice.id, {
        identity_signature: base64UrlEncode(identitySignature),
      })

      // Step 11: Store device keys using DSK
      setStatusMessage('Saving device keys…')
      const dsk = await generateDsk()
      await storeDsk(dsk)
      await wrapAndStoreDeviceKeys(newDeviceKeyPair, dsk, sessionResponse.user_id)
      await storeDeviceId(approvalResponse.id)
      await wrapAndStoreUmk(umk, dsk, sessionResponse.user_id)

      // Set PoP credentials for future API calls
      setPopCredentials(approvalResponse.id, newDeviceKeyPair.signingPrivateKey)

      // Step 12: Set auth state
      setAuthState({
        userId: sessionResponse.user_id,
        email: sessionResponse.email,
        expiresAt: new Date(sessionResponse.expires_at),
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
  }, [words, email, navigate, setAuthState, setDeviceState])

  const handleClear = () => {
    setWords(Array(24).fill(''))
    setEmail('')
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
                <div className="flex items-center justify-between">
                  <Label>Recovery Phrase</Label>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    Upload File
                  </Button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </div>
                <p className="text-xs text-muted-foreground mb-4">
                  Upload your recovery key file or enter each word manually. You can also paste the full 24-word phrase into the first field.
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
