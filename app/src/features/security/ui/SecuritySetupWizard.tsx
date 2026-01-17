import { Shield, Key, CheckCircle2, Lock, Loader2 } from 'lucide-react'
import { useState, useCallback, useEffect, useRef } from 'react'
import { useNavigate } from '@tanstack/react-router'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Progress } from '@/shared/ui/progress'

import {
  registerPublicKey,
  storeMasterKeyBackup,
  storeEncryptedPrivateKey,
  markSecuritySetupComplete,
} from '@/entities/user'

import { useE2EE } from '../context/e2ee-context'
import { useSecurityStatus } from '../hooks/useSecurityStatus'
import { toBase64, fromBase64 } from '../lib/crypto'
import { performMigration, type MigrationProgress } from '../lib/migration'

import { PassphraseInput } from './PassphraseInput'
import { RecoveryKeyDisplay } from './RecoveryKeyDisplay'
import { RecoveryKeyVerify } from './RecoveryKeyVerify'

type WizardStep =
  | 'intro'
  | 'passphrase'
  | 'migrating'
  | 'recovery-display'
  | 'recovery-verify'
  | 'complete'

interface SetupState {
  passphrase: string | null
  recoveryKey: string | null
  publicKeys: { ecdhPublicKey: string; signingPublicKey: string } | null
  salt: Uint8Array | null
  kdf: 'argon2id' | 'pbkdf2' | null
  kdfParams: { memory?: number; iterations: number; parallelism?: number } | null
}

const STEP_TITLES: Record<WizardStep, string> = {
  intro: 'Security Setup',
  passphrase: 'Set Passphrase',
  migrating: 'Encrypting Data',
  'recovery-display': 'Save Recovery Key',
  'recovery-verify': 'Verify Recovery Key',
  complete: 'Setup Complete',
}

export function SecuritySetupWizard() {
  const navigate = useNavigate()
  const { setupE2EE, error: e2eeError } = useE2EE()
  const { refetch: refetchSecurityStatus } = useSecurityStatus()

  const [currentStep, setCurrentStep] = useState<WizardStep>('intro')
  const [setupState, setSetupState] = useState<SetupState>({
    passphrase: null,
    recoveryKey: null,
    publicKeys: null,
    salt: null,
    kdf: null,
    kdfParams: null,
  })
  const [error, setError] = useState<string | null>(null)
  // Track the entire submission process (including API calls after setupE2EE)
  const [isSubmitting, setIsSubmitting] = useState(false)
  // Migration progress
  const [migrationProgress, setMigrationProgress] = useState<MigrationProgress | null>(null)
  // Prevent double migration
  const migrationStarted = useRef(false)

  // Handle passphrase submission
  const handlePassphraseSubmit = useCallback(
    async (passphrase: string) => {
      setError(null)
      setIsSubmitting(true)
      try {
        const result = await setupE2EE(passphrase)

        // Register ECDH public key
        await registerPublicKey({
          keyType: 'x25519',
          publicKey: result.publicKeys.ecdhPublicKey,
        })

        // Register signing public key
        await registerPublicKey({
          keyType: 'ed25519',
          publicKey: result.publicKeys.signingPublicKey,
        })

        // Store master key backup (salt and KDF params for key derivation)
        const saltBase64 = await toBase64(result.salt)
        await storeMasterKeyBackup({
          encryptedKey: saltBase64, // Not used for decryption, just for API compatibility
          salt: saltBase64,
          kdfType: result.kdf,
          kdfParams: {
            iterations: result.kdfParams.iterations,
            memory: result.kdfParams.memory ?? null,
            parallelism: result.kdfParams.parallelism ?? null,
          },
        })

        // Store encrypted private keys as JSON bundle
        const keysBundle = JSON.stringify(result.encryptedKeysBundle)
        const keysBundleBase64 = btoa(keysBundle)
        // nonce must be valid base64 - use 'bundle-v1' encoded as base64
        const nonceBase64 = btoa('bundle-v1')
        await storeEncryptedPrivateKey({
          encryptedPrivateKey: keysBundleBase64,
          nonce: nonceBase64,
        })

        setSetupState({
          passphrase,
          recoveryKey: result.recoveryKey,
          publicKeys: result.publicKeys,
          salt: result.salt,
          kdf: result.kdf,
          kdfParams: result.kdfParams,
        })
        setIsSubmitting(false)
        // Move to migration step
        setCurrentStep('migrating')
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Setup failed'
        setError(message)
        setIsSubmitting(false)
      }
    },
    [setupE2EE]
  )

  // Run migration when we enter the migrating step
  useEffect(() => {
    if (currentStep !== 'migrating') return
    if (migrationStarted.current) return
    if (!setupState.publicKeys) return

    migrationStarted.current = true

    const runMigration = async () => {
      try {
        // Get user's public key as Uint8Array for encryption
        const publicKeyBytes = await fromBase64(setupState.publicKeys!.ecdhPublicKey)

        // Get user ID from me() API
        const { me } = await import('@/entities/user')
        const userInfo = await me()

        // Perform migration
        await performMigration(
          publicKeyBytes,
          userInfo.id,
          (progress) => setMigrationProgress(progress)
        )

        // Migration complete, move to recovery display
        setCurrentStep('recovery-display')
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Migration failed'
        setError(message)
        migrationStarted.current = false
      }
    }

    runMigration()
  }, [currentStep, setupState.publicKeys])

  // Handle recovery key display confirmation
  const handleRecoveryDisplayConfirm = useCallback(() => {
    setCurrentStep('recovery-verify')
  }, [])

  // Handle recovery key verification
  const handleRecoveryVerified = useCallback(async () => {
    try {
      // Mark E2EE setup as complete
      await markSecuritySetupComplete()
      // Invalidate security status cache
      refetchSecurityStatus()
      setCurrentStep('complete')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to complete setup'
      setError(message)
    }
  }, [refetchSecurityStatus])

  // Handle completion
  const handleComplete = useCallback(() => {
    navigate({ to: '/dashboard' })
  }, [navigate])

  return (
    <div className="mx-auto max-w-lg">
      <Card>
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <StepIcon step={currentStep} />
          </div>
          <CardTitle>{STEP_TITLES[currentStep]}</CardTitle>
          <CardDescription>
            <StepDescription step={currentStep} />
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Intro Step */}
          {currentStep === 'intro' && (
            <IntroStep onContinue={() => setCurrentStep('passphrase')} />
          )}

          {/* Passphrase Step */}
          {currentStep === 'passphrase' && (
            <PassphraseInput
              onSubmit={handlePassphraseSubmit}
              loading={isSubmitting}
              error={error ?? e2eeError ?? undefined}
            />
          )}

          {/* Migrating Step */}
          {currentStep === 'migrating' && (
            <MigratingStep progress={migrationProgress} error={error} />
          )}

          {/* Recovery Display Step */}
          {currentStep === 'recovery-display' && setupState.recoveryKey && (
            <RecoveryKeyDisplay
              recoveryKey={setupState.recoveryKey}
              onConfirm={handleRecoveryDisplayConfirm}
            />
          )}

          {/* Recovery Verify Step */}
          {currentStep === 'recovery-verify' && setupState.recoveryKey && (
            <RecoveryKeyVerify
              recoveryKey={setupState.recoveryKey}
              onVerified={handleRecoveryVerified}
              onBack={() => setCurrentStep('recovery-display')}
            />
          )}

          {/* Complete Step */}
          {currentStep === 'complete' && (
            <CompleteStep onContinue={handleComplete} />
          )}

          {/* Global Error */}
          {error && currentStep !== 'passphrase' && (
            <p className="mt-4 text-sm text-destructive">{error}</p>
          )}
        </CardContent>
      </Card>

      {/* Progress Indicator */}
      <div className="mt-6 flex justify-center gap-2">
        {(['intro', 'passphrase', 'migrating', 'recovery-display', 'recovery-verify', 'complete'] as const).map(
          (step, index) => (
            <div
              key={step}
              className={cn(
                'h-2 w-2 rounded-full transition-colors',
                getStepIndex(currentStep) >= index ? 'bg-primary' : 'bg-muted'
              )}
            />
          )
        )}
      </div>
    </div>
  )
}

function StepIcon({ step }: { step: WizardStep }) {
  switch (step) {
    case 'intro':
      return <Shield className="h-6 w-6 text-primary" />
    case 'passphrase':
      return <Lock className="h-6 w-6 text-primary" />
    case 'migrating':
      return <Loader2 className="h-6 w-6 text-primary animate-spin" />
    case 'recovery-display':
    case 'recovery-verify':
      return <Key className="h-6 w-6 text-primary" />
    case 'complete':
      return <CheckCircle2 className="h-6 w-6 text-green-500" />
  }
}

function StepDescription({ step }: { step: WizardStep }) {
  switch (step) {
    case 'intro':
      return 'Configure security settings to protect your account'
    case 'passphrase':
      return 'Set a passphrase to encrypt your data'
    case 'migrating':
      return 'Encrypting your existing data with end-to-end encryption'
    case 'recovery-display':
      return 'This recovery key is used if you forget your passphrase'
    case 'recovery-verify':
      return 'Confirm that your recovery key has been saved correctly'
    case 'complete':
      return 'Security setup is complete'
  }
}

function IntroStep({ onContinue }: { onContinue: () => void }) {
  return (
    <div className="space-y-6">
      <div className="space-y-4 text-sm text-muted-foreground">
        <p>
          RefMD protects your data with end-to-end encryption (E2EE).
        </p>
        <ul className="space-y-2">
          <li className="flex items-start gap-2">
            <Shield className="h-4 w-4 mt-0.5 text-primary shrink-0" />
            <span>
              <strong className="text-foreground">Full encryption:</strong>{' '}
              Your data is encrypted on your device and cannot be read
              even by our servers
            </span>
          </li>
          <li className="flex items-start gap-2">
            <Lock className="h-4 w-4 mt-0.5 text-primary shrink-0" />
            <span>
              <strong className="text-foreground">Passphrase protection:</strong>{' '}
              Your data is protected by a passphrase.
              This passphrase is never stored on our servers
            </span>
          </li>
          <li className="flex items-start gap-2">
            <Key className="h-4 w-4 mt-0.5 text-primary shrink-0" />
            <span>
              <strong className="text-foreground">Recovery key:</strong>{' '}
              Even if you forget your passphrase,
              you can recover your account with the recovery key
            </span>
          </li>
        </ul>
      </div>
      <Button onClick={onContinue} className="w-full">
        Start Setup
      </Button>
    </div>
  )
}

function CompleteStep({ onContinue }: { onContinue: () => void }) {
  return (
    <div className="space-y-6 text-center">
      <div className="space-y-2">
        <p className="text-lg font-medium text-green-600">
          Security setup complete
        </p>
        <p className="text-sm text-muted-foreground">
          Your data is now encrypted and securely protected.
          You can start using the app.
        </p>
      </div>
      <Button onClick={onContinue} className="w-full">
        Go to Dashboard
      </Button>
    </div>
  )
}

function MigratingStep({ progress, error }: { progress: MigrationProgress | null; error: string | null }) {
  const progressPercent = progress && progress.total > 0
    ? Math.round((progress.current / progress.total) * 100)
    : 0

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <div className="flex items-center justify-center">
          <Loader2 className="h-12 w-12 text-primary animate-spin" />
        </div>
        <div className="space-y-2">
          <p className="text-center text-sm text-muted-foreground">
            {progress?.message ?? 'Preparing...'}
          </p>
          {progress && progress.total > 0 && (
            <div className="space-y-1">
              <Progress value={progressPercent} className="h-2" />
              <p className="text-center text-xs text-muted-foreground">
                {progress.current} / {progress.total}
              </p>
            </div>
          )}
        </div>
      </div>
      {error && (
        <p className="text-sm text-destructive text-center">{error}</p>
      )}
      <p className="text-center text-xs text-muted-foreground">
        Please do not close this window.
      </p>
    </div>
  )
}

function getStepIndex(step: WizardStep): number {
  const steps: WizardStep[] = [
    'intro',
    'passphrase',
    'migrating',
    'recovery-display',
    'recovery-verify',
    'complete',
  ]
  return steps.indexOf(step)
}
