import type * as Y from 'yjs'
import type { TofuVerifyResult } from '@/shared/lib/crypto'

export interface TofuKeyChangeWarning {
  deviceId: string
  oldFingerprint: string
  newFingerprint: string
  tofuResult: TofuVerifyResult
}

export interface DocumentState {
  yDoc: Y.Doc
  dek: Uint8Array
  keyVersion: number
  lastSavedState: Uint8Array | null
  prevUpdateHash: string | null
  isDirty: boolean
  isSaving: boolean
  contentListeners: Set<(content: string) => void>
  refCount: number
}
