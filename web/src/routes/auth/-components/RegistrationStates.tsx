/**
 * Device Registration UI States
 *
 * Display components for the various states of the device registration flow.
 */

import { Button } from '@/shared/ui/button'
import { Spinner } from '@/shared/ui/spinner'
import { SasVerification } from '@/features/device'
import { KeyChangeWarningDialog } from '@/shared/ui/KeyChangeWarningDialog'
import type { KeyChangeWarningDialogProps } from '@/shared/hooks'
import { ErrorAlert } from '@/shared/ui/error-alert'
import { AuthLayout } from './AuthLayout'

function ErrorActions({ onRetry, onCancel }: { onRetry: () => void; onCancel: () => void }) {
  return (
    <>
      <Button className="w-full" onClick={onRetry}>Try Again</Button>
      <Button variant="outline" className="w-full" onClick={onCancel}>Back to Login</Button>
    </>
  )
}

export function KeyChangeWarningPage(props: KeyChangeWarningDialogProps) {
  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <KeyChangeWarningDialog {...props} />
    </main>
  )
}

export function RegistrationLoadingState({ deviceName, error, onRetry, onCancel }: {
  deviceName: string
  error: string | null
  onRetry: () => void
  onCancel: () => void
}) {
  return (
    <AuthLayout title="Registering Device" description={`Setting up ${deviceName}`}>
      <div className="space-y-4">
        {error ? (
          <>
            <ErrorAlert>{error}</ErrorAlert>
            <ErrorActions onRetry={onRetry} onCancel={onCancel} />
          </>
        ) : (
          <>
            <div className="flex justify-center py-8">
              <Spinner />
            </div>
            <Button variant="outline" className="w-full" onClick={onCancel}>Cancel</Button>
          </>
        )}
      </div>
    </AuthLayout>
  )
}

export function RegistrationWaitingState({ sasEmojis, error, onRetry, onCancel }: {
  sasEmojis: string | null
  error: string | null
  onRetry: () => void
  onCancel: () => void
}) {
  return (
    <AuthLayout
      title={error ? 'Registration Failed' : 'Waiting for Approval'}
      description={error ? 'A security issue was detected' : 'Verify the emojis on your existing device'}
    >
      <div className="space-y-6">
        {error ? (
          <>
            <ErrorAlert>{error}</ErrorAlert>
            <ErrorActions onRetry={onRetry} onCancel={onCancel} />
          </>
        ) : (
          <>
            {sasEmojis ? (
              <SasVerification emojis={sasEmojis} role="new" />
            ) : (
              <div className="flex justify-center py-8">
                <Spinner />
              </div>
            )}
            <div className="text-center text-sm text-muted-foreground">
              <p>Open RefMD on your existing device and approve this device.</p>
              <p className="mt-2">The emojis must match exactly.</p>
            </div>
            <Button variant="outline" className="w-full" onClick={onCancel}>Cancel</Button>
          </>
        )}
      </div>
    </AuthLayout>
  )
}

export function RegistrationErrorState({ error, onRetry, onCancel }: {
  error: string
  onRetry: () => void
  onCancel: () => void
}) {
  return (
    <AuthLayout
      title="Registration Failed"
      titleClassName="text-destructive"
      description="An error occurred during device registration"
    >
      <div className="space-y-4">
        <ErrorAlert>{error}</ErrorAlert>
        <ErrorActions onRetry={onRetry} onCancel={onCancel} />
      </div>
    </AuthLayout>
  )
}
