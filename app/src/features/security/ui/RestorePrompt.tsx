import { Download, Lock, Key, AlertCircle, Loader2 } from 'lucide-react'
import { useState, useCallback } from 'react'

import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { useKeyVault } from '../context/key-vault-context'

type RestoreMode = 'passphrase' | 'recovery'

interface RestorePromptProps {
  /** Called when restore is successful */
  onRestored?: () => void
  /** Whether to show the component inline (no card wrapper) */
  inline?: boolean
}

export function RestorePrompt({ onRestored, inline = false }: RestorePromptProps) {
  const {
    restoreFromServer,
    restoreFromServerWithRecoveryKey,
    loading,
    error,
    clearError,
  } = useKeyVault()
  const [mode, setMode] = useState<RestoreMode>('passphrase')
  const [passphrase, setPassphrase] = useState('')
  const [recoveryKey, setRecoveryKey] = useState('')

  const handlePassphraseSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      if (!passphrase.trim() || loading) return

      try {
        await restoreFromServer(passphrase)
        onRestored?.()
      } catch {
        // Error is handled by context
      }
    },
    [passphrase, loading, restoreFromServer, onRestored]
  )

  const handleRecoverySubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      if (!recoveryKey.trim() || loading) return

      try {
        await restoreFromServerWithRecoveryKey(recoveryKey)
        onRestored?.()
      } catch {
        // Error is handled by context
      }
    },
    [recoveryKey, loading, restoreFromServerWithRecoveryKey, onRestored]
  )

  const switchMode = useCallback(
    (newMode: RestoreMode) => {
      setMode(newMode)
      clearError()
      setPassphrase('')
      setRecoveryKey('')
    },
    [clearError]
  )

  const content = (
    <div className="space-y-6">
      {/* Info Banner */}
      <div className="rounded-lg bg-blue-50 dark:bg-blue-950 p-4 text-sm text-blue-800 dark:text-blue-200">
        <div className="flex items-start gap-3">
          <Download className="h-5 w-5 mt-0.5 shrink-0" />
          <div>
            <p className="font-medium">New device detected</p>
            <p className="mt-1 text-blue-600 dark:text-blue-300">
              Your encryption keys will be restored from the server backup.
              Enter your passphrase to decrypt them.
            </p>
          </div>
        </div>
      </div>

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
            <Label htmlFor="restore-passphrase">Passphrase</Label>
            <Input
              id="restore-passphrase"
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter your passphrase"
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
                Restoring keys...
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                Restore Keys
              </>
            )}
          </Button>
        </form>
      )}

      {/* Recovery Key Form */}
      {mode === 'recovery' && (
        <form onSubmit={handleRecoverySubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="restore-recovery">Recovery Key</Label>
            <textarea
              id="restore-recovery"
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
                Restoring keys...
              </>
            ) : (
              <>
                <Key className="mr-2 h-4 w-4" />
                Restore with Recovery Key
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
            <Download className="h-6 w-6 text-primary" />
          </div>
          <CardTitle>Restore Encryption Keys</CardTitle>
          <CardDescription>
            Your encryption keys were found on the server.
            Enter your passphrase to restore them to this device.
          </CardDescription>
        </CardHeader>
        <CardContent>{content}</CardContent>
      </Card>
    </div>
  )
}
