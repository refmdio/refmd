import { AlertTriangle, Key, RefreshCw, ShieldAlert, X } from 'lucide-react'

import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/shared/ui/alert-dialog'
import { Button } from '@/shared/ui/button'

import { type CryptoError, ERROR_CODES } from '../lib/types/errors'

type RecoveryAction = 'retry' | 'recovery_key' | 'contact_admin' | 'close'

interface DecryptionErrorDialogProps {
  /** Whether the dialog is open */
  open: boolean
  /** Callback when open state changes */
  onOpenChange: (open: boolean) => void
  /** The error that occurred */
  error: CryptoError | null
  /** Document ID (for context display) */
  documentId?: string
  /** Callback when retry is requested */
  onRetry?: () => void
  /** Callback when recovery key input is requested */
  onRecoveryKey?: () => void
}

/**
 * Determine the appropriate recovery actions based on error code
 */
function getRecoveryActions(error: CryptoError): RecoveryAction[] {
  switch (error.code) {
    case ERROR_CODES.SIGNATURE_INVALID:
      // Data may be tampered - contact admin
      return ['contact_admin', 'close']

    case ERROR_CODES.DECRYPTION_FAILED:
    case ERROR_CODES.KEY_NOT_FOUND:
    case ERROR_CODES.KEY_INVALID:
      // Key issues - try recovery key
      return ['recovery_key', 'retry', 'close']

    case ERROR_CODES.FILE_CORRUPTED:
      // File corrupted - not much we can do
      return ['contact_admin', 'close']

    case ERROR_CODES.NETWORK_FAILED:
    case ERROR_CODES.SYNC_TIMEOUT:
      // Network issues - retry
      return ['retry', 'close']

    default:
      return ['retry', 'close']
  }
}

/**
 * Get icon for error type
 */
function ErrorIcon({ error }: { error: CryptoError }) {
  switch (error.code) {
    case ERROR_CODES.SIGNATURE_INVALID:
      return <ShieldAlert className="h-6 w-6 text-destructive" />
    case ERROR_CODES.KEY_NOT_FOUND:
    case ERROR_CODES.KEY_INVALID:
      return <Key className="h-6 w-6 text-amber-500" />
    default:
      return <AlertTriangle className="h-6 w-6 text-destructive" />
  }
}

/**
 * Get title for error type
 */
function getErrorTitle(error: CryptoError): string {
  switch (error.code) {
    case ERROR_CODES.SIGNATURE_INVALID:
      return 'Data Integrity Error'
    case ERROR_CODES.KEY_NOT_FOUND:
      return 'Encryption Key Missing'
    case ERROR_CODES.KEY_INVALID:
      return 'Invalid Encryption Key'
    case ERROR_CODES.DECRYPTION_FAILED:
      return 'Decryption Failed'
    case ERROR_CODES.FILE_CORRUPTED:
      return 'File Corrupted'
    case ERROR_CODES.NETWORK_FAILED:
      return 'Network Error'
    default:
      return 'Error'
  }
}

/**
 * Get description for error type
 */
function getErrorDescription(error: CryptoError): string {
  switch (error.code) {
    case ERROR_CODES.SIGNATURE_INVALID:
      return 'The document signature is invalid. This could indicate that the content has been tampered with or corrupted.'
    case ERROR_CODES.KEY_NOT_FOUND:
      return 'The encryption key for this document was not found. You may need to restore your keys using your recovery key.'
    case ERROR_CODES.KEY_INVALID:
      return 'The encryption key is invalid. Try entering your passphrase again or use your recovery key.'
    case ERROR_CODES.DECRYPTION_FAILED:
      return 'Failed to decrypt the content. The data may be corrupted or your encryption keys may need to be restored.'
    case ERROR_CODES.FILE_CORRUPTED:
      return 'The file appears to be corrupted and cannot be opened.'
    default:
      return error.getUserMessage()
  }
}

export function DecryptionErrorDialog({
  open,
  onOpenChange,
  error,
  documentId,
  onRetry,
  onRecoveryKey,
}: DecryptionErrorDialogProps) {
  if (!error) return null

  const actions = getRecoveryActions(error)

  const handleAction = (action: RecoveryAction) => {
    switch (action) {
      case 'retry':
        onRetry?.()
        onOpenChange(false)
        break
      case 'recovery_key':
        onRecoveryKey?.()
        onOpenChange(false)
        break
      case 'contact_admin':
        // For now, just close - in the future could open support dialog
        onOpenChange(false)
        break
      case 'close':
        onOpenChange(false)
        break
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-destructive/10">
              <ErrorIcon error={error} />
            </div>
            <div className="space-y-1">
              <AlertDialogTitle>{getErrorTitle(error)}</AlertDialogTitle>
              {documentId && (
                <p className="text-xs text-muted-foreground font-mono">
                  Document: {documentId.slice(0, 8)}...
                </p>
              )}
            </div>
          </div>
        </AlertDialogHeader>

        <AlertDialogDescription className="space-y-3">
          <p>{getErrorDescription(error)}</p>

          {error.code === ERROR_CODES.SIGNATURE_INVALID && (
            <div className="rounded-md bg-destructive/10 p-3 text-sm">
              <p className="font-medium text-destructive">Security Warning</p>
              <p className="mt-1 text-destructive/80">
                If you did not expect this document to be modified, please contact your workspace administrator.
              </p>
            </div>
          )}

          <p className="text-xs text-muted-foreground">
            Error code: {error.code}
          </p>
        </AlertDialogDescription>

        <AlertDialogFooter>
          {actions.includes('contact_admin') && (
            <Button
              variant="outline"
              onClick={() => handleAction('contact_admin')}
            >
              Contact Administrator
            </Button>
          )}

          {actions.includes('retry') && onRetry && (
            <Button
              variant="outline"
              onClick={() => handleAction('retry')}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Retry
            </Button>
          )}

          {actions.includes('recovery_key') && onRecoveryKey && (
            <Button onClick={() => handleAction('recovery_key')}>
              <Key className="mr-2 h-4 w-4" />
              Use Recovery Key
            </Button>
          )}

          {actions.includes('close') && !actions.includes('recovery_key') && (
            <Button variant="outline" onClick={() => handleAction('close')}>
              <X className="mr-2 h-4 w-4" />
              Close
            </Button>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
