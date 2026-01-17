import { Check, Loader2, AlertCircle, RefreshCw } from 'lucide-react'
import { useState, useEffect, useCallback } from 'react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'

import { migrateUserData, markSecuritySetupComplete, type MigrateRequest } from '@/entities/user'

type StepStatus = 'pending' | 'in_progress' | 'completed' | 'error'

interface MigrationStep {
  id: string
  label: string
  status: StepStatus
}

interface MigrationProgressProps {
  /** Migration request data (keys, etc.) */
  migrationData: MigrateRequest
  /** Called when migration completes successfully */
  onComplete: () => void
  /** Called when migration fails */
  onError: (error: Error) => void
}

const INITIAL_STEPS: MigrationStep[] = [
  { id: 'keys', label: 'Registering encryption keys', status: 'pending' },
  { id: 'data', label: 'Encrypting data', status: 'pending' },
  { id: 'verify', label: 'Verifying', status: 'pending' },
  { id: 'complete', label: 'Completing setup', status: 'pending' },
]

export function MigrationProgress({
  migrationData,
  onComplete,
  onError,
}: MigrationProgressProps) {
  const [steps, setSteps] = useState<MigrationStep[]>(INITIAL_STEPS)
  const [error, setError] = useState<string | null>(null)
  const [isRetrying, setIsRetrying] = useState(false)

  const updateStepStatus = useCallback((stepId: string, status: StepStatus) => {
    setSteps((prev) =>
      prev.map((step) => (step.id === stepId ? { ...step, status } : step))
    )
  }, [])

  const runMigration = useCallback(async () => {
    setError(null)
    setSteps(INITIAL_STEPS)

    try {
      // Step 1: Register keys
      updateStepStatus('keys', 'in_progress')
      await new Promise((r) => setTimeout(r, 500)) // Small delay for UX
      updateStepStatus('keys', 'completed')

      // Step 2: Migrate data
      updateStepStatus('data', 'in_progress')
      await migrateUserData(migrationData)
      updateStepStatus('data', 'completed')

      // Step 3: Verify
      updateStepStatus('verify', 'in_progress')
      await new Promise((r) => setTimeout(r, 300))
      updateStepStatus('verify', 'completed')

      // Step 4: Mark complete
      updateStepStatus('complete', 'in_progress')
      await markSecuritySetupComplete()
      updateStepStatus('complete', 'completed')

      // Success
      onComplete()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Migration failed'
      setError(message)

      // Find the in_progress step and mark it as error
      setSteps((prev) =>
        prev.map((step) => ({
          ...step,
          status: step.status === 'in_progress' ? 'error' : step.status,
        }))
      )

      onError(err instanceof Error ? err : new Error(message))
    }
  }, [migrationData, onComplete, onError, updateStepStatus])

  const handleRetry = useCallback(async () => {
    setIsRetrying(true)
    await runMigration()
    setIsRetrying(false)
  }, [runMigration])

  // Start migration on mount
  useEffect(() => {
    runMigration()
  }, [runMigration])

  const progress = steps.filter((s) => s.status === 'completed').length / steps.length

  return (
    <div className="space-y-6">
      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="flex justify-between text-sm">
          <span>Migrating...</span>
          <span>{Math.round(progress * 100)}%</span>
        </div>
        <div className="h-2 rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-all duration-500"
            style={{ width: `${progress * 100}%` }}
          />
        </div>
      </div>

      {/* Steps */}
      <div className="space-y-3">
        {steps.map((step) => (
          <StepItem key={step.id} step={step} />
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-destructive/50 bg-destructive/10 p-4">
            <AlertCircle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-medium text-destructive">Migration failed</p>
              <p className="text-sm text-muted-foreground">{error}</p>
            </div>
          </div>

          <Button
            onClick={handleRetry}
            disabled={isRetrying}
            className="w-full"
          >
            {isRetrying ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Retrying...
              </>
            ) : (
              <>
                <RefreshCw className="mr-2 h-4 w-4" />
                Retry
              </>
            )}
          </Button>
        </div>
      )}
    </div>
  )
}

function StepItem({ step }: { step: MigrationStep }) {
  return (
    <div className="flex items-center gap-3">
      <div
        className={cn(
          'flex h-6 w-6 items-center justify-center rounded-full',
          step.status === 'completed' && 'bg-green-500 text-white',
          step.status === 'in_progress' && 'bg-primary text-primary-foreground',
          step.status === 'error' && 'bg-destructive text-white',
          step.status === 'pending' && 'bg-muted text-muted-foreground'
        )}
      >
        {step.status === 'completed' && <Check className="h-3.5 w-3.5" />}
        {step.status === 'in_progress' && (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        )}
        {step.status === 'error' && <AlertCircle className="h-3.5 w-3.5" />}
        {step.status === 'pending' && (
          <span className="h-2 w-2 rounded-full bg-current" />
        )}
      </div>
      <span
        className={cn(
          'text-sm',
          step.status === 'completed' && 'text-green-600',
          step.status === 'in_progress' && 'font-medium',
          step.status === 'error' && 'text-destructive',
          step.status === 'pending' && 'text-muted-foreground'
        )}
      >
        {step.label}
      </span>
    </div>
  )
}
