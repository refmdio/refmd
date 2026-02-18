/**
 * Key Change Warning Types
 *
 * Pure data types for key change warning UI flows.
 * Placed in shared/model (not shared/hooks) so that pure service code
 * in features/{feature}/lib can depend on these without coupling to React hooks.
 */

import type { TofuEntry } from '@/shared/lib/trust-store'

export interface KeyChangeWarningItem {
  displayName: string
  oldFingerprint: string
  newFingerprint: string
  tofuNewEntry: TofuEntry
}

export interface KeyChangeWarningDialogProps {
  open: boolean
  deviceName: string
  oldFingerprint: string
  newFingerprint: string
  onTrust: () => void
  onBlock: () => void
  onCancel: () => void
}
