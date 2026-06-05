"use client"

import {
  AlertTriangle,
  BookOpen,
  Bug,
  CheckCircle2,
  FileText,
  List,
  ListTree,
  MessageSquare,
  PanelRight,
  Search,
  Tags,
  type LucideIcon,
} from 'lucide-react'
import type { ReactNode } from 'react'

const documentPaneIcons: Record<string, LucideIcon> = {
  'alert-triangle': AlertTriangle,
  'book-open': BookOpen,
  bug: Bug,
  'check-circle': CheckCircle2,
  'check-circle-2': CheckCircle2,
  comments: MessageSquare,
  'file-text': FileText,
  list: List,
  'list-tree': ListTree,
  'message-square': MessageSquare,
  'panel-right': PanelRight,
  search: Search,
  tags: Tags,
}

function normalizeDocumentPaneIconName(icon?: string | null) {
  return String(icon ?? '')
    .trim()
    .toLowerCase()
    .replace(/[_\s]+/g, '-')
}

export function renderDocumentPaneIcon(icon?: string | null, className = 'h-4 w-4'): ReactNode {
  const Icon = documentPaneIcons[normalizeDocumentPaneIconName(icon)] ?? PanelRight
  return <Icon className={className} aria-hidden="true" />
}
