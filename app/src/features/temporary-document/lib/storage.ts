export type TemporaryDocumentMeta = {
  id: string
  createdAt: number
  updatedAt: number
  preview?: string
  length?: number
}

const LIST_STORAGE_KEY = 'refmd:temporary-documents:list'
export const TEMPORARY_DOCUMENT_PERSISTENCE_PREFIX = 'refmd:temporary-document'
export const TEMPORARY_DOCUMENT_TTL_MS = 24 * 60 * 60 * 1000

const hasWindow = () => typeof window !== 'undefined'

const now = () => Date.now()

const generateId = () => {
  if (hasWindow()) {
    const cryptoObj = window.crypto || (window as any).msCrypto
    if (cryptoObj?.randomUUID) {
      try {
        return cryptoObj.randomUUID() as string
      } catch {}
    }
  }
  return `temp-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`
}

function readList(): TemporaryDocumentMeta[] {
  if (!hasWindow()) return []
  try {
    const raw = window.localStorage.getItem(LIST_STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as TemporaryDocumentMeta[] | null
    if (!Array.isArray(parsed)) return []
    return parsed.filter((entry) => typeof entry?.id === 'string' && typeof entry?.updatedAt === 'number')
  } catch {
    return []
  }
}

function writeList(list: TemporaryDocumentMeta[]) {
  if (!hasWindow()) return
  try {
    window.localStorage.setItem(LIST_STORAGE_KEY, JSON.stringify(list))
  } catch {}
}

function purgeExpired(list: TemporaryDocumentMeta[]) {
  const cutoff = now() - TEMPORARY_DOCUMENT_TTL_MS
  const next: TemporaryDocumentMeta[] = []
  for (const entry of list) {
    if (entry.updatedAt >= cutoff) {
      next.push(entry)
    } else {
      clearPersistence(entry.id)
    }
  }
  return next
}

function clearPersistence(id: string) {
  if (!hasWindow()) return
  try {
    window.indexedDB?.deleteDatabase?.(`${TEMPORARY_DOCUMENT_PERSISTENCE_PREFIX}:${id}`)
  } catch {}
}

export function listTemporaryDocuments() {
  const list = purgeExpired(readList())
  writeList(list)
  return list
}

export function getTemporaryDocumentEntry(id: string) {
  return listTemporaryDocuments().find((entry) => entry.id === id)
}

export function createTemporaryDocumentEntry() {
  const entry: TemporaryDocumentMeta = {
    id: generateId(),
    createdAt: now(),
    updatedAt: now(),
  }
  const list = listTemporaryDocuments()
  list.push(entry)
  writeList(list)
  return entry
}

export function updateTemporaryDocumentEntry(id: string, updates: Partial<Omit<TemporaryDocumentMeta, 'id'>>) {
  const list = listTemporaryDocuments()
  const idx = list.findIndex((entry) => entry.id === id)
  if (idx === -1) {
    const created: TemporaryDocumentMeta = {
      id,
      createdAt: updates.createdAt ?? now(),
      updatedAt: updates.updatedAt ?? now(),
      preview: updates.preview,
      length: updates.length,
    }
    list.push(created)
    writeList(list)
    return created
  }
  const next = {
    ...list[idx],
    ...updates,
    updatedAt: updates.updatedAt ?? now(),
  }
  list[idx] = next
  writeList(list)
  return next
}

export function deleteTemporaryDocumentEntry(id: string) {
  const list = listTemporaryDocuments()
  const next = list.filter((entry) => entry.id !== id)
  writeList(next)
  clearPersistence(id)
}

export function touchTemporaryDocumentEntry(id: string, preview: string, length: number) {
  updateTemporaryDocumentEntry(id, {
    updatedAt: now(),
    length,
    preview,
  })
}
