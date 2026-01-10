import { ArrowLeft, Check, X } from 'lucide-react'
import { useState, useCallback, useMemo } from 'react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { generateVerificationIndices, getWordsAtIndices } from '../lib/crypto/bip39'

interface RecoveryKeyVerifyProps {
  /** Recovery key (24 words space-separated) */
  recoveryKey: string
  /** Called when verification is successful */
  onVerified: () => void
  /** Called when user wants to go back */
  onBack: () => void
}

export function RecoveryKeyVerify({
  recoveryKey,
  onVerified,
  onBack,
}: RecoveryKeyVerifyProps) {
  const [confirmChecked, setConfirmChecked] = useState(false)
  const [inputs, setInputs] = useState<Record<number, string>>({})
  const [error, setError] = useState<string | null>(null)

  // Generate random indices to verify (2 random words)
  const verificationIndices = useMemo(() => {
    return generateVerificationIndices(2)
  }, [])

  // Get expected words at those indices
  const expectedWords = useMemo(() => {
    return getWordsAtIndices(recoveryKey, verificationIndices)
  }, [recoveryKey, verificationIndices])

  // Check if current inputs match
  const isCorrect = useMemo(() => {
    return verificationIndices.every((index, i) => {
      const input = inputs[index]?.toLowerCase().trim()
      const expected = expectedWords[i]?.toLowerCase()
      return input === expected
    })
  }, [inputs, verificationIndices, expectedWords])

  const isComplete = useMemo(() => {
    return verificationIndices.every((index) => {
      const input = inputs[index]?.trim()
      return input && input.length > 0
    })
  }, [inputs, verificationIndices])

  const handleInputChange = useCallback((index: number, value: string) => {
    setInputs((prev) => ({ ...prev, [index]: value }))
    setError(null)
  }, [])

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()

      if (!confirmChecked) {
        setError('Please confirm you have saved the recovery key')
        return
      }

      if (!isCorrect) {
        setError('The entered words are incorrect')
        return
      }

      onVerified()
    },
    [confirmChecked, isCorrect, onVerified]
  )

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Instructions */}
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">
          To confirm that you have correctly saved your recovery key,
          please enter the following words.
        </p>
      </div>

      {/* Word Inputs */}
      <div className="space-y-4">
        {verificationIndices.map((index, i) => (
          <WordInput
            key={index}
            index={index}
            value={inputs[index] || ''}
            onChange={(value) => handleInputChange(index, value)}
            isCorrect={
              inputs[index]?.toLowerCase().trim() === expectedWords[i]?.toLowerCase()
            }
            showValidation={!!inputs[index]?.trim()}
          />
        ))}
      </div>

      {/* Confirmation Checkbox */}
      <div className="space-y-4">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={confirmChecked}
            onChange={(e) => setConfirmChecked(e.target.checked)}
            className="mt-1 h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
          />
          <span className="text-sm">
            I have saved my recovery key in a secure location (password manager,
            safe, or written on paper). I understand that losing this key means
            I will not be able to recover my account.
          </span>
        </label>
      </div>

      {/* Error Message */}
      {error && (
        <p className="text-sm text-destructive">{error}</p>
      )}

      {/* Action Buttons */}
      <div className="flex gap-3">
        <Button
          type="button"
          variant="outline"
          onClick={onBack}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back
        </Button>
        <Button
          type="submit"
          className="flex-1"
          disabled={!isComplete || !confirmChecked}
        >
          Verify and continue
        </Button>
      </div>
    </form>
  )
}

function WordInput({
  index,
  value,
  onChange,
  isCorrect,
  showValidation,
}: {
  index: number
  value: string
  onChange: (value: string) => void
  isCorrect: boolean
  showValidation: boolean
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={`word-${index}`}>
        Word #{index + 1}
      </Label>
      <div className="relative">
        <Input
          id={`word-${index}`}
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Enter word"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          className={cn(
            'pr-10',
            showValidation && (isCorrect ? 'border-green-500' : 'border-destructive')
          )}
        />
        {showValidation && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            {isCorrect ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : (
              <X className="h-4 w-4 text-destructive" />
            )}
          </div>
        )}
      </div>
    </div>
  )
}
