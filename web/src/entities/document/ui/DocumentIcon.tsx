import { FileText, Folder, Archive } from 'lucide-react'

interface DocumentIconProps {
  docType: string
  isArchived: boolean
  className?: string
}

export function DocumentIcon({ docType, isArchived, className = 'h-5 w-5' }: DocumentIconProps) {
  if (isArchived) return <Archive className={className} />
  if (docType === 'folder') return <Folder className={className} />
  return <FileText className={className} />
}
