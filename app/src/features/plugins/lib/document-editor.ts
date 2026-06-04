"use client"

import type { ManifestItem } from '@/shared/api'

export type DocumentEditorRange = {
  startLineNumber: number
  startColumn: number
  endLineNumber: number
  endColumn: number
}

export type DocumentEditorSelection = DocumentEditorRange & {
  text: string
  isEmpty: boolean
}

export type DocumentEditorDecorationInput = {
  id?: string
  range: DocumentEditorRange
  className?: string
  inlineClassName?: string
  glyphMarginClassName?: string
  hoverMessage?: string
  overviewRulerColor?: string
  minimapColor?: string
}

export type DocumentEditorEditInput = {
  range: DocumentEditorRange
  text: string
  forceMoveMarkers?: boolean
}

export type DocumentEditorHiddenRangeInput = {
  range: DocumentEditorRange
}

export type DocumentEditorApi = {
  focus(): void
  getSelection(): DocumentEditorSelection | null
  setSelection(range: DocumentEditorRange): void
  applyEdits(edits: DocumentEditorEditInput[]): boolean
  replaceSelection(text: string): boolean
  insertText(text: string): boolean
  revealLine(line: number): void
  revealRange(range: DocumentEditorRange): void
  getRangeFromOffset(offset: number, length?: number): DocumentEditorRange | null
  getOffsetFromPosition(position: { lineNumber: number; column: number }): number | null
  onSelectionChange(callback: (selection: DocumentEditorSelection | null) => void): () => void
  setDecorations(ownerId: string, decorations: DocumentEditorDecorationInput[]): () => void
  setHiddenRanges(ownerId: string, ranges: DocumentEditorHiddenRangeInput[]): () => void
}

export type DocumentEditorDocumentApi = {
  id: string
  type?: string | null
  title?: string | null
  token?: string | null
  readOnly: boolean
  getContent(): string
  setContent(value: string): boolean
  onContentChange(callback: (content: string) => void): () => void
}

export type DocumentEditorPaneRenderContext = {
  plugin: {
    id: string
    version: string
    manifest: ManifestItem
  }
  document: DocumentEditorDocumentApi
  editor: DocumentEditorApi
  pane: {
    id: string
    active: boolean
    close(): void
    onActiveChange(callback: (active: boolean) => void): () => void
  }
}

export type DocumentEditorPaneContribution = {
  id: string
  title: string
  order?: number
  icon?: string
  render(
    container: HTMLElement,
    ctx: DocumentEditorPaneRenderContext,
  ): void | (() => void)
}

export type DocumentEditorPaneRegistration = {
  dispose(): void
  setBadge(value: string | number | null): void
  setTitle(title: string): void
  open(): void
}

export type DocumentEditorRecordApi = {
  list(kind: string, options?: { limit?: number; offset?: number }): Promise<unknown[]>
  create(kind: string, data: unknown): Promise<unknown>
  update(id: string, patch: unknown): Promise<unknown>
  delete(id: string): Promise<void>
}

export type DocumentEditorKvApi = {
  get(key: string): Promise<unknown>
  put(key: string, value: unknown): Promise<unknown>
}

export type DocumentEditorActivationContext = {
  plugin: {
    id: string
    version: string
    manifest: ManifestItem
  }
  document: DocumentEditorDocumentApi
  editor: DocumentEditorApi
  documentPanes: {
    register(pane: DocumentEditorPaneContribution): DocumentEditorPaneRegistration
  }
  records: DocumentEditorRecordApi
  kv: DocumentEditorKvApi
  toast(level: 'info' | 'success' | 'warning' | 'error', message: string): void
}

export type DocumentEditorPluginMatch = {
  manifest: ManifestItem
  module: any
}

export type RegisteredDocumentEditorPane = {
  key: string
  pluginId: string
  pluginVersion: string
  pluginManifest: ManifestItem
  id: string
  title: string
  order: number
  icon?: string
  badge: string | number | null
  contribution: DocumentEditorPaneContribution
}
