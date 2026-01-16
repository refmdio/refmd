import { Eye, EyeOff, Check, X } from 'lucide-react'
import { useState, useCallback, useMemo, useEffect } from 'react'
import zxcvbn from 'zxcvbn'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

const MIN_PASSPHRASE_LENGTH = 12

interface PassphraseInputProps {
  onSubmit: (passphrase: string) => void | Promise<void>
  loading?: boolean
  error?: string
  requireConfirmation?: boolean
  minLength?: number
  submitLabel?: string
}

interface StrengthInfo {
  score: number
  label: string
  color: string
  feedback: string[]
}

function getStrengthInfo(result: zxcvbn.ZXCVBNResult): StrengthInfo {
  const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']
  const colors = [
    'bg-red-500',
    'bg-orange-500',
    'bg-yellow-500',
    'bg-lime-500',
    'bg-green-500',
  ]

  const feedback = [
    ...result.feedback.suggestions,
    result.feedback.warning,
  ].filter(Boolean) as string[]

  return {
    score: result.score,
    label: labels[result.score],
    color: colors[result.score],
    feedback,
  }
}

export function PassphraseInput({
  onSubmit,
  loading = false,
  error,
  requireConfirmation = true,
  minLength = MIN_PASSPHRASE_LENGTH,
  submitLabel = 'Next',
}: PassphraseInputProps) {
  const [passphrase, setPassphrase] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [showPassphrase, setShowPassphrase] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [touched, setTouched] = useState(false)

  const strength = useMemo(() => {
    if (!passphrase) return null
    return getStrengthInfo(zxcvbn(passphrase))
  }, [passphrase])

  const validations = useMemo(() => {
    return {
      minLength: passphrase.length >= minLength,
      strongEnough: strength ? strength.score >= 2 : false,
      matches: !requireConfirmation || passphrase === confirmation,
    }
  }, [passphrase, confirmation, minLength, strength, requireConfirmation])

  const isValid = validations.minLength && validations.strongEnough && validations.matches

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      setTouched(true)
      if (isValid && !loading) {
        try {
          await onSubmit(passphrase)
        } catch {
          // Error is handled by the parent component via error prop
        }
      }
    },
    [isValid, loading, onSubmit, passphrase]
  )

  // Clear confirmation when passphrase changes
  useEffect(() => {
    if (requireConfirmation && passphrase !== confirmation && confirmation) {
      // Keep confirmation as-is, validation will show mismatch
    }
  }, [passphrase, confirmation, requireConfirmation])

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Passphrase Input */}
      <div className="space-y-2">
        <Label htmlFor="passphrase">Passphrase</Label>
        <div className="relative">
          <Input
            id="passphrase"
            type={showPassphrase ? 'text' : 'password'}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            onBlur={() => setTouched(true)}
            placeholder={`${minLength}+ characters`}
            autoComplete="new-password"
            aria-invalid={touched && !validations.minLength}
            disabled={loading}
            className="pr-10"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
            onClick={() => setShowPassphrase(!showPassphrase)}
            tabIndex={-1}
          >
            {showPassphrase ? (
              <EyeOff className="h-4 w-4 text-muted-foreground" />
            ) : (
              <Eye className="h-4 w-4 text-muted-foreground" />
            )}
          </Button>
        </div>

        {/* Strength Meter */}
        {passphrase && strength && (
          <div className="space-y-2">
            <div className="flex gap-1">
              {[0, 1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className={cn(
                    'h-1.5 flex-1 rounded-full transition-colors',
                    i <= strength.score ? strength.color : 'bg-muted'
                  )}
                />
              ))}
            </div>
            <div className="flex justify-between text-xs">
              <span className={cn('font-medium', strength.score >= 2 ? 'text-green-600' : 'text-destructive')}>
                {strength.label}
              </span>
              {strength.feedback.length > 0 && (
                <span className="text-muted-foreground">
                  {strength.feedback[0]}
                </span>
              )}
            </div>
          </div>
        )}

        {/* Validation Checklist */}
        <div className="space-y-1 text-sm">
          <ValidationItem
            valid={validations.minLength}
            label={`${minLength}+ characters`}
            touched={touched || passphrase.length > 0}
          />
          <ValidationItem
            valid={validations.strongEnough}
            label="Strong enough"
            touched={touched || passphrase.length > 0}
          />
        </div>
      </div>

      {/* Confirmation Input */}
      {requireConfirmation && (
        <div className="space-y-2">
          <Label htmlFor="confirmation">Confirm passphrase</Label>
          <div className="relative">
            <Input
              id="confirmation"
              type={showConfirmation ? 'text' : 'password'}
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              placeholder="Enter again"
              autoComplete="new-password"
              aria-invalid={touched && confirmation.length > 0 && !validations.matches}
              disabled={loading}
              className="pr-10"
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
              onClick={() => setShowConfirmation(!showConfirmation)}
              tabIndex={-1}
            >
              {showConfirmation ? (
                <EyeOff className="h-4 w-4 text-muted-foreground" />
              ) : (
                <Eye className="h-4 w-4 text-muted-foreground" />
              )}
            </Button>
          </div>
          {confirmation && !validations.matches && (
            <p className="text-sm text-destructive">Passphrases do not match</p>
          )}
        </div>
      )}

      {/* Error Message */}
      {error && (
        <p className="text-sm text-destructive">{error}</p>
      )}

      {/* Submit Button */}
      <Button
        type="submit"
        className="w-full"
        disabled={!isValid || loading}
      >
        {loading ? 'Processing...' : submitLabel}
      </Button>
    </form>
  )
}

function ValidationItem({
  valid,
  label,
  touched,
}: {
  valid: boolean
  label: string
  touched: boolean
}) {
  if (!touched) {
    return (
      <div className="flex items-center gap-2 text-muted-foreground">
        <div className="h-4 w-4" />
        <span>{label}</span>
      </div>
    )
  }

  return (
    <div className={cn('flex items-center gap-2', valid ? 'text-green-600' : 'text-destructive')}>
      {valid ? <Check className="h-4 w-4" /> : <X className="h-4 w-4" />}
      <span>{label}</span>
    </div>
  )
}
