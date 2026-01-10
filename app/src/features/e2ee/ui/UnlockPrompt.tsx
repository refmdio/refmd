import { Lock, Key, AlertCircle, Loader2 } from 'lucide-react'
import { useState, useCallback } from 'react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { useKeyManager } from '../hooks/useKeyManager'

type UnlockMode = 'passphrase' | 'recovery'

interface UnlockPromptProps {
  /** Called when unlock is successful */
  onUnlocked?: () => void
  /** Whether to show the component inline (no card wrapper) */
  inline?: boolean
  /** Custom title */
  title?: string
  /** Custom description */
  description?: string
}

export function UnlockPrompt({
  onUnlocked,
  inline = false,
  title = 'Unlock your data',
  description = 'Enter your passphrase to access your data',
}: UnlockPromptProps) {
  const { unlock, unlockWithRecoveryKey, loading, error, clearError } = useKeyManager()
  const [mode, setMode] = useState<UnlockMode>('passphrase')
  const [passphrase, setPassphrase] = useState('')
  const [recoveryKey, setRecoveryKey] = useState('')

  const handlePassphraseSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      if (!passphrase.trim() || loading) return

      try {
        await unlock(passphrase)
        onUnlocked?.()
      } catch {
        // Error is handled by useKeyManager
      }
    },
    [passphrase, loading, unlock, onUnlocked]
  )

  const handleRecoverySubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      if (!recoveryKey.trim() || loading) return

      try {
        await unlockWithRecoveryKey(recoveryKey)
        onUnlocked?.()
      } catch {
        // Error is handled by useKeyManager
      }
    },
    [recoveryKey, loading, unlockWithRecoveryKey, onUnlocked]
  )

  const switchMode = useCallback(
    (newMode: UnlockMode) => {
      setMode(newMode)
      clearError()
      setPassphrase('')
      setRecoveryKey('')
    },
    [clearError]
  )

  const content = (
    <div className="space-y-6">
      {/* Mode Tabs */}
      <div className="flex rounded-lg bg-muted p-1">
        <button
          type="button"
          onClick={() => switchMode('passphrase')}
          className={cn(
            'flex-1 rounded-md px-3 py-2 text-sm font-medium transition-colors',
            mode === 'passphrase'
              ? 'bg-background text-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <Lock className="mr-2 inline-block h-4 w-4" />
          Passphrase
        </button>
        <button
          type="button"
          onClick={() => switchMode('recovery')}
          className={cn(
            'flex-1 rounded-md px-3 py-2 text-sm font-medium transition-colors',
            mode === 'recovery'
              ? 'bg-background text-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <Key className="mr-2 inline-block h-4 w-4" />
          Recovery Key
        </button>
      </div>

      {/* Passphrase Form */}
      {mode === 'passphrase' && (
        <form onSubmit={handlePassphraseSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="unlock-passphrase">Passphrase</Label>
            <Input
              id="unlock-passphrase"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter passphrase"
              autoComplete="current-password"
              disabled={loading}
            />
          </div>

          {error && (
            <div className="flex items-start gap-2 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <Button type="submit" className="w-full" disabled={!passphrase.trim() || loading}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Unlocking...
              </>
            ) : (
              <>
                <Lock className="mr-2 h-4 w-4" />
                Unlock
              </>
            )}
          </Button>
        </form>
      )}

      {/* Recovery Key Form */}
      {mode === 'recovery' && (
        <form onSubmit={handleRecoverySubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="unlock-recovery">Recovery Key</Label>
            <textarea
              id="unlock-recovery"
              value={recoveryKey}
              onChange={(e) => setRecoveryKey(e.target.value)}
              placeholder="Enter your 24-word recovery key (space-separated)"
              className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              disabled={loading}
            />
            <p className="text-xs text-muted-foreground">
              Enter the 24-word recovery key you saved during setup
            </p>
          </div>

          {error && (
            <div className="flex items-start gap-2 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <Button type="submit" className="w-full" disabled={!recoveryKey.trim() || loading}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Recovering...
              </>
            ) : (
              <>
                <Key className="mr-2 h-4 w-4" />
                Recover with key
              </>
            )}
          </Button>
        </form>
      )}
    </div>
  )

  if (inline) {
    return content
  }

  return (
    <div className="mx-auto max-w-md">
      <Card>
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <Lock className="h-6 w-6 text-primary" />
          </div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>{content}</CardContent>
      </Card>
    </div>
  )
}
