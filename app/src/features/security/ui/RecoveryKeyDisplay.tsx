import { Copy, Download, Eye, EyeOff, AlertTriangle } from 'lucide-react'
import { useState, useCallback, useMemo } from 'react'
import { toast } from 'sonner'

import { cn } from '@/shared/lib/utils'
import { Alert, AlertDescription } from '@/shared/ui/alert'
import { Button } from '@/shared/ui/button'

interface RecoveryKeyDisplayProps {
  /** Recovery key (24 words space-separated) */
  recoveryKey: string
  /** Called when user confirms they have saved the key */
  onConfirm: () => void
}

export function RecoveryKeyDisplay({ recoveryKey, onConfirm }: RecoveryKeyDisplayProps) {
  const [isRevealed, setIsRevealed] = useState(false)
  const [hasCopied, setHasCopied] = useState(false)

  const words = useMemo(() => recoveryKey.split(' '), [recoveryKey])

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(recoveryKey)
      setHasCopied(true)
      toast.success('Recovery key copied to clipboard')
    } catch {
      toast.error('Failed to copy')
    }
  }, [recoveryKey])

  const handleDownload = useCallback(() => {
    const content = `RefMD Recovery Key
====================

Please store this file in a secure location.
If you forget your passphrase, you can restore your account with this recovery key.

Recovery Key (24 words):
${words.map((word, i) => `${(i + 1).toString().padStart(2, ' ')}. ${word}`).join('\n')}

Warning:
- Do not share this file with anyone
- Do not store it in cloud storage
- We recommend writing it down on paper and storing it in a safe place

Generated: ${new Date().toISOString()}
`

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'refmd-recovery-key.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    toast.success('Recovery key downloaded')
  }, [words])

  return (
    <div className="space-y-6">
      {/* Warning Alert */}
      <Alert variant="destructive" className="border-orange-500 bg-orange-50 dark:bg-orange-950/20">
        <AlertTriangle className="h-4 w-4 text-orange-600" />
        <AlertDescription className="text-orange-800 dark:text-orange-200">
          <strong>Important:</strong> This recovery key will not be shown again.
          Please save it in a secure location. If you forget your passphrase,
          you will not be able to recover your account without this key.
        </AlertDescription>
      </Alert>

      {/* Recovery Key Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Recovery Key (24 words)</span>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setIsRevealed(!isRevealed)}
          >
            {isRevealed ? (
              <>
                <EyeOff className="mr-2 h-4 w-4" />
                Hide
              </>
            ) : (
              <>
                <Eye className="mr-2 h-4 w-4" />
                Show
              </>
            )}
          </Button>
        </div>

        <div
          className={cn(
            'grid grid-cols-3 gap-2 rounded-lg border bg-muted/50 p-4',
            !isRevealed && 'select-none'
          )}
        >
          {words.map((word, index) => (
            <div
              key={index}
              className="flex items-center gap-2 rounded bg-background px-2 py-1.5 text-sm"
            >
              <span className="w-5 text-right text-muted-foreground">
                {index + 1}.
              </span>
              <span className={cn('font-mono', !isRevealed && 'blur-sm')}>
                {word}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex gap-3">
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={handleCopy}
        >
          <Copy className="mr-2 h-4 w-4" />
          Copy
        </Button>
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={handleDownload}
        >
          <Download className="mr-2 h-4 w-4" />
          Download
        </Button>
      </div>

      {/* Confirm Button */}
      <Button
        type="button"
        className="w-full"
        onClick={onConfirm}
        disabled={!hasCopied && !isRevealed}
      >
        I have saved it, continue
      </Button>

      {!hasCopied && !isRevealed && (
        <p className="text-center text-sm text-muted-foreground">
          Please reveal or copy your recovery key before continuing
        </p>
      )}
    </div>
  )
}
