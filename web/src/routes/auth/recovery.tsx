/**
 * Recovery Page
 *
 * Allows users to recover their account using the 24-word BIP39 mnemonic.
 * This is used when the user has lost access to all their devices
 * and needs to restore their UMK (User Master Key).
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState, useRef, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { isValidMnemonic, deriveRukFromMnemonic, unwrapUmkWithRuk, base64UrlDecode } from '@/shared/lib/crypto'
import { authApi } from '@/shared/api'

export const Route = createFileRoute('/auth/recovery')({
  component: RecoveryPage,
})

function RecoveryPage() {
  const navigate = useNavigate()
  const [words, setWords] = useState<string[]>(Array(24).fill(''))
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [step, setStep] = useState<'input' | 'validating' | 'success'>('input')
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus()
  }, [])

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    const mnemonic = words.join(' ')

    // Validate mnemonic
    if (!isValidMnemonic(mnemonic)) {
      setError('Invalid recovery phrase. Please check all 24 words.')
      return
    }

    setLoading(true)
    setStep('validating')

    try {
      // TODO: Implement actual recovery flow
      // 1. Check if user has an account (via /api/auth/salt with email)
      // 2. Derive RUK from mnemonic
      // 3. Get recovery-wrapped UMK from server
      // 4. Unwrap UMK with RUK
      // 5. Generate new device keys
      // 6. Register as new device
      // 7. Login user

      // For now, just show a message that recovery is in progress
      setError('Recovery functionality is under development. Please use an existing device to approve this device.')
      setStep('input')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recovery failed')
      setStep('input')
    } finally {
      setLoading(false)
    }
  }

  const handleClear = () => {
    setWords(Array(24).fill(''))
    setError(null)
    inputRefs.current[0]?.focus()
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold">Account Recovery</CardTitle>
          <CardDescription>
            Enter your 24-word recovery phrase to restore access to your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label>Recovery Phrase</Label>
              <p className="text-xs text-muted-foreground mb-4">
                Enter each word in order. You can paste the full 24-word phrase into the first field.
              </p>

              <div className="grid grid-cols-4 gap-2">
                {words.map((word, index) => (
                  <div key={index} className="flex items-center gap-1">
                    <span className="text-xs text-muted-foreground w-5 text-right">
                      {index + 1}.
                    </span>
                    <Input
                      ref={(el) => { inputRefs.current[index] = el }}
                      type="text"
                      value={word}
                      onChange={(e) => handleWordChange(index, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(index, e)}
                      placeholder="word"
                      disabled={loading}
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
              <Button type="submit" className="flex-1" disabled={loading}>
                {loading ? 'Recovering...' : 'Recover Account'}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={handleClear}
                disabled={loading}
              >
                Clear
              </Button>
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

          <div className="mt-6 p-4 bg-muted rounded-lg">
            <h4 className="font-semibold text-sm mb-2">Important Security Notes</h4>
            <ul className="text-xs text-muted-foreground space-y-1">
              <li>Never share your recovery phrase with anyone</li>
              <li>RefMD staff will never ask for your recovery phrase</li>
              <li>Make sure you're on the official RefMD website</li>
              <li>After recovery, you should re-enable device verification</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </main>
  )
}
