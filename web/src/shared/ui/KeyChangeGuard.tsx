import type { KeyChangeWarningDialogProps } from '@/shared/hooks'
import { KeyChangeWarningDialog } from './KeyChangeWarningDialog'

interface KeyChangeGuardProps {
  dialogProps: KeyChangeWarningDialogProps | null | undefined
  children: React.ReactNode
}

/**
 * Renders KeyChangeWarningDialog when dialogProps is active,
 * otherwise renders children. Eliminates the repeated
 * `if (x.keyChangeDialogProps) return <KeyChangeWarningDialog />` pattern.
 */
export function KeyChangeGuard({ dialogProps, children }: KeyChangeGuardProps) {
  if (dialogProps) return <KeyChangeWarningDialog {...dialogProps} />
  return <>{children}</>
}
