/**
 * Recovery Page
 *
 * Allows users to recover their account using the 24-word BIP39 mnemonic.
 * This is used when the user has lost access to all their devices
 * and needs to restore their UMK (User Master Key).
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState, useCallback, useEffect, useRef } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { isValidMnemonic } from '@/shared/lib/crypto'
import { useRecoveryFlow, type RecoveryStep } from '@/features/auth'
import { selfApproveDevice } from '@/features/device'
import { parseRecoveryKeyFile } from '@/shared/lib/recovery-key-format'
import { ErrorAlert } from '@/shared/ui/error-alert'
import { useAuthContext } from '@/shared/context'
import { RecoveryLoadingState, RecoverySuccessState, MnemonicWordGrid } from './-components/RecoveryStates'
import { AuthLayout } from './-components/AuthLayout'

export const Route = createFileRoute('/auth/recovery')({
  component: RecoveryPage,
})

const MAX_FILE_SIZE = 10 * 1024
const EMPTY_MNEMONIC = (): string[] => Array(24).fill('')

function RecoveryPage() {
  const navigate = useNavigate()
  const { setFullSession } = useAuthContext()
  const [step, setStep] = useState<RecoveryStep>('input')
  const [words, setWords] = useState<string[]>(EMPTY_MNEMONIC())
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [statusMessage, setStatusMessage] = useState('')
  const redirectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (redirectTimerRef.current !== null) clearTimeout(redirectTimerRef.current)
    }
  }, [])

  const { handleSubmit: executeRecovery } = useRecoveryFlow({
    selfApproveDevice,
    setFullSession,
    setStep,
    setStatusMessage,
    setError: (msg: string) => setError(msg),
    onSuccess: () => {
      redirectTimerRef.current = setTimeout(() => {
        navigate({ to: '/' })
      }, 1500)
    },
  })

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    if (file.size > MAX_FILE_SIZE) {
      setError('File is too large. Recovery key files should be less than 10KB.')
      e.target.value = ''
      return
    }

    try {
      const content = await file.text()
      const result = parseRecoveryKeyFile(content)

      if ('error' in result) {
        setError(result.error)
        setWords(EMPTY_MNEMONIC())
      } else {
        const mnemonic = result.words.join(' ')
        if (!isValidMnemonic(mnemonic)) {
          setError('Invalid recovery key file: contains invalid BIP39 words.')
          setWords(EMPTY_MNEMONIC())
        } else {
          setWords(result.words)
          setError(null)
        }
      }
    } catch {
      setError('Failed to read file.')
      setWords(EMPTY_MNEMONIC())
    }

    e.target.value = ''
  }

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    await executeRecovery(email, words)
  }, [email, words, executeRecovery])

  const handleClear = () => {
    setWords(EMPTY_MNEMONIC())
    setEmail('')
    setError(null)
    setStep('input')
  }

  return (
    <AuthLayout
      title="Account Recovery"
      description="Restore access to your account using your 24-word recovery phrase"
      maxWidth="2xl"
    >
      {step === 'recovering' && (
        <RecoveryLoadingState statusMessage={statusMessage} />
      )}

      {step === 'success' && <RecoverySuccessState />}

      {(step === 'input' || step === 'error') && (
        <form onSubmit={handleSubmit} className="space-y-6">
          {error && <ErrorAlert>{error}</ErrorAlert>}

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

          <MnemonicWordGrid
            words={words}
            onWordsChange={setWords}
            onFileUpload={handleFileUpload}
          />

          <div className="flex gap-2">
            <Button type="submit" className="flex-1">
              Recover Account
            </Button>
            {step === 'error' ? (
              <Button type="button" variant="outline" onClick={() => { setStep('input'); setError(null) }}>
                Try Again
              </Button>
            ) : (
              <Button type="button" variant="outline" onClick={handleClear}>
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
    </AuthLayout>
  )
}
