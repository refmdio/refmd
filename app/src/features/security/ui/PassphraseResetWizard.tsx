import { AlertCircle, ArrowLeft, ArrowRight, Check, Key, Loader2, Lock } from 'lucide-react'
import { useState, useCallback } from 'react'

import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'

import { useE2EE } from '../context/e2ee-context'
import { useKeyManager } from '../hooks/useKeyManager'
import { PassphraseInput } from './PassphraseInput'
import { RecoveryKeyDisplay } from './RecoveryKeyDisplay'

type ResetStep = 'recovery_input' | 'new_passphrase' | 'new_recovery_display' | 'complete'

interface PassphraseResetWizardProps {
  /** Called when the reset process is complete */
  onComplete?: () => void
  /** Called when the user cancels */
  onCancel?: () => void
}

export function PassphraseResetWizard({
  onComplete,
  onCancel,
}: PassphraseResetWizardProps) {
  const { unlockWithRecovery } = useE2EE()
  const { changePassphrase } = useKeyManager()

  const [step, setStep] = useState<ResetStep>('recovery_input')
  const [recoveryKey, setRecoveryKey] = useState('')
  const [newRecoveryKey, setNewRecoveryKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Step 1: Validate recovery key and unlock
  const handleRecoveryKeySubmit = useCallback(async () => {
    if (!recoveryKey.trim()) return

    setLoading(true)
    setError(null)

    try {
      // Validate format
      const words = recoveryKey.trim().split(/\s+/)
      if (words.length !== 24) {
        throw new Error('Recovery key must be exactly 24 words')
      }

      // Unlock with recovery key (uses rememberMe from auth context)
      await unlockWithRecovery(recoveryKey)

      // Move to next step
      setStep('new_passphrase')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid recovery key')
    } finally {
      setLoading(false)
    }
  }, [recoveryKey, unlockWithRecovery])

  // Step 2: Set new passphrase and generate new recovery key
  const handleNewPassphraseSubmit = useCallback(async (passphrase: string) => {
    setLoading(true)
    setError(null)

    try {
      // Change passphrase (this will also generate a new recovery key)
      const result = await changePassphrase(passphrase)
      setNewRecoveryKey(result)
      setStep('new_recovery_display')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset passphrase')
    } finally {
      setLoading(false)
    }
  }, [changePassphrase])

  // Step 3: User has seen the new recovery key
  const handleRecoveryKeyConfirmed = useCallback(() => {
    setStep('complete')
  }, [])

  // Step 4: Complete
  const handleComplete = useCallback(() => {
    onComplete?.()
  }, [onComplete])

  const renderStep = () => {
    switch (step) {
      case 'recovery_input':
        return (
          <>
            <CardHeader>
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900">
                <Key className="h-6 w-6 text-amber-600 dark:text-amber-400" />
              </div>
              <CardTitle className="text-center">Reset Passphrase</CardTitle>
              <CardDescription className="text-center">
                Enter your 24-word recovery key to reset your passphrase
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <textarea
                  value={recoveryKey}
                  onChange={(e) => setRecoveryKey(e.target.value)}
                  placeholder="Enter your 24-word recovery key (space-separated)"
                  className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                  disabled={loading}
                />
                <p className="text-xs text-muted-foreground">
                  This is the 24-word phrase you saved when you set up encryption
                </p>
              </div>

              {error && (
                <div className="flex items-start gap-2 text-sm text-destructive">
                  <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex gap-2">
                {onCancel && (
                  <Button variant="outline" onClick={onCancel} disabled={loading}>
                    <ArrowLeft className="mr-2 h-4 w-4" />
                    Back
                  </Button>
                )}
                <Button
                  className="flex-1"
                  onClick={handleRecoveryKeySubmit}
                  disabled={!recoveryKey.trim() || loading}
                >
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Verifying...
                    </>
                  ) : (
                    <>
                      Continue
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </>
        )

      case 'new_passphrase':
        return (
          <>
            <CardHeader>
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
                <Lock className="h-6 w-6 text-primary" />
              </div>
              <CardTitle className="text-center">Set New Passphrase</CardTitle>
              <CardDescription className="text-center">
                Create a strong passphrase to protect your data
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <PassphraseInput
                onSubmit={handleNewPassphraseSubmit}
                loading={loading}
                error={error ?? undefined}
                submitLabel="Reset Passphrase"
              />

              <Button
                variant="outline"
                onClick={() => setStep('recovery_input')}
                disabled={loading}
                className="w-full"
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Button>
            </CardContent>
          </>
        )

      case 'new_recovery_display':
        return (
          <>
            <CardHeader>
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
                <Key className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <CardTitle className="text-center">Save Your New Recovery Key</CardTitle>
              <CardDescription className="text-center">
                Your passphrase has been reset. Save this new recovery key in a safe place.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <RecoveryKeyDisplay
                recoveryKey={newRecoveryKey}
                onConfirm={handleRecoveryKeyConfirmed}
              />
            </CardContent>
          </>
        )

      case 'complete':
        return (
          <>
            <CardHeader>
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
                <Check className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <CardTitle className="text-center">Passphrase Reset Complete</CardTitle>
              <CardDescription className="text-center">
                Your passphrase has been successfully reset. You can now use your new passphrase to unlock your data.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button className="w-full" onClick={handleComplete}>
                Continue
              </Button>
            </CardContent>
          </>
        )
    }
  }

  return (
    <div className="mx-auto max-w-md">
      <Card>{renderStep()}</Card>
    </div>
  )
}
