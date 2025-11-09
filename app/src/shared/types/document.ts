import type { ReactNode } from 'react'

export type DocumentHeaderAction = {
  id?: string
  label: string
  onSelect?: () => void
  disabled?: boolean
  variant?: 'default' | 'primary' | 'outline'
  icon?: ReactNode
  tooltip?: string
}
