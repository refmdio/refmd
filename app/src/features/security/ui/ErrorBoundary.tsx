import { AlertTriangle, Key, RefreshCw } from 'lucide-react'
import { Component, type ReactNode } from 'react'

import {
  CryptoError,
  ERROR_CATEGORY,
  ERROR_CODES,
  isCryptoError,
} from '@/shared/types/security'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'


import { logError } from '../lib/error-log/log-error'

interface ErrorBoundaryProps {
  /** Children to render */
  children: ReactNode
  /** Fallback UI when error is not a CryptoError */
  fallback?: ReactNode
  /** Called when an error occurs */
  onError?: (error: Error) => void
  /** Called when recovery key input is requested */
  onRecoveryKey?: () => void
  /** Called when retry is requested */
  onRetry?: () => void
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
  cryptoError: CryptoError | null
}

/**
 * Error Boundary for E2EE errors
 *
 * Catches CryptoError instances and displays appropriate recovery UI.
 *
 * @example
 * ```tsx
 * <ErrorBoundary onRecoveryKey={() => navigate('/recovery')}>
 *   <EncryptedContent />
 * </ErrorBoundary>
 * ```
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      cryptoError: null,
    }
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
      cryptoError: isCryptoError(error) ? error : null,
    }
  }

  componentDidCatch(error: Error): void {
    // Log the error
    if (isCryptoError(error)) {
      logError(error).catch(console.error)
    }

    // Call optional error handler
    this.props.onError?.(error)
  }

  handleRetry = (): void => {
    this.setState({
      hasError: false,
      error: null,
      cryptoError: null,
    })
    this.props.onRetry?.()
  }

  handleRecoveryKey = (): void => {
    this.props.onRecoveryKey?.()
  }

  render(): ReactNode {
    const { hasError, error, cryptoError } = this.state
    const { children, fallback } = this.props

    if (!hasError) {
      return children
    }

    // If it's a CryptoError, show specialized UI
    if (cryptoError) {
      return <CryptoErrorFallback error={cryptoError} onRetry={this.handleRetry} onRecoveryKey={this.handleRecoveryKey} />
    }

    // If a custom fallback is provided, use it
    if (fallback) {
      return fallback
    }

    // Default fallback for non-crypto errors
    return (
      <DefaultErrorFallback
        error={error}
        onRetry={this.handleRetry}
      />
    )
  }
}

interface CryptoErrorFallbackProps {
  error: CryptoError
  onRetry: () => void
  onRecoveryKey?: () => void
}

function CryptoErrorFallback({ error, onRetry, onRecoveryKey }: CryptoErrorFallbackProps) {
  const showRecoveryButton =
    error.code === ERROR_CODES.KEY_NOT_FOUND ||
    error.code === ERROR_CODES.KEY_INVALID ||
    error.code === ERROR_CODES.DECRYPTION_FAILED ||
    error.code === ERROR_CODES.SESSION_LOCKED

  const isCritical = error.category === ERROR_CATEGORY.CRITICAL

  return (
    <div className="flex min-h-[400px] items-center justify-center p-8">
      <Card className="max-w-md">
        <CardHeader className="text-center">
          <div
            className={`mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full ${
              isCritical ? 'bg-destructive/10' : 'bg-amber-100 dark:bg-amber-900'
            }`}
          >
            {showRecoveryButton ? (
              <Key
                className={`h-6 w-6 ${
                  isCritical ? 'text-destructive' : 'text-amber-600 dark:text-amber-400'
                }`}
              />
            ) : (
              <AlertTriangle
                className={`h-6 w-6 ${
                  isCritical ? 'text-destructive' : 'text-amber-600 dark:text-amber-400'
                }`}
              />
            )}
          </div>
          <CardTitle>
            {isCritical ? 'Encryption Error' : 'Something went wrong'}
          </CardTitle>
          <CardDescription>{error.getUserMessage()}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-center text-xs text-muted-foreground">
            Error code: {error.code}
          </p>

          <div className="flex flex-col gap-2">
            {showRecoveryButton && onRecoveryKey && (
              <Button onClick={onRecoveryKey}>
                <Key className="mr-2 h-4 w-4" />
                Use Recovery Key
              </Button>
            )}
            <Button variant="outline" onClick={onRetry}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Try Again
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

interface DefaultErrorFallbackProps {
  error: Error | null
  onRetry: () => void
}

function DefaultErrorFallback({ error, onRetry }: DefaultErrorFallbackProps) {
  return (
    <div className="flex min-h-[400px] items-center justify-center p-8">
      <Card className="max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
            <AlertTriangle className="h-6 w-6 text-destructive" />
          </div>
          <CardTitle>Something went wrong</CardTitle>
          <CardDescription>
            {error?.message ?? 'An unexpected error occurred'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button className="w-full" variant="outline" onClick={onRetry}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Try Again
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
