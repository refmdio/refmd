import { createFileRoute, useNavigate, useParams } from '@tanstack/react-router'
import { Save, Trash2 } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { toast } from 'sonner'

import { Button } from '@/shared/ui/button'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { createDocument, updateDocumentContent } from '@/entities/document'

import { appBeforeLoadGuard, useAuthContext } from '@/features/auth'
import { EditorOverlay, MarkdownEditor } from '@/features/edit-document'
import { TEMPORARY_DOCUMENT_TTL_MS, useTemporaryDocument } from '@/features/temporary-document'


import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

import { useRealtime } from '@/processes/collaboration'

export const Route = createFileRoute('/(app)/temporary/$id')({
  staticData: { layout: 'app' },
  beforeLoad: appBeforeLoadGuard,
  pendingComponent: () => <RoutePending label="Preparing temporary document…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: TemporaryDocumentPage,
})

function TemporaryDocumentPage() {
  const { id } = useParams({ from: '/(app)/temporary/$id' })
  return <TemporaryDocumentEditor tempId={id} />
}

function TemporaryDocumentEditor({ tempId }: { tempId: string }) {
  const navigate = useNavigate()
  const { user } = useAuthContext()
  const { setDocumentTitle, setDocumentBadge, setDocumentStatus, setDocumentActions, setShowEditorFeatures, setDocumentId } = useRealtime()
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const tempDoc = useTemporaryDocument({ id: tempId, user: user ? { id: user.id, name: user.name } : undefined })
  const { doc, awareness, status, error, hasContent, lastUpdatedAt, removeEntry, getContentSnapshot } = tempDoc
  const [expiryLabel, setExpiryLabel] = useState(() => formatExpiryLabel(lastUpdatedAt))

  useEffect(() => {
    setDocumentTitle('Temporary document')
    setDocumentBadge('Local only')
    setDocumentId(undefined)
    setShowEditorFeatures(true)
    return () => {
      setDocumentTitle(undefined)
      setDocumentBadge(undefined)
      setDocumentStatus(undefined)
      setDocumentId(undefined)
      setShowEditorFeatures(false)
    }
  }, [setDocumentTitle, setDocumentBadge, setShowEditorFeatures, setDocumentId])

  useEffect(() => {
    const updateLabel = () => {
      setExpiryLabel(formatExpiryLabel(lastUpdatedAt))
    }
    updateLabel()
    if (typeof window === 'undefined') return
    const interval = window.setInterval(updateLabel, 60 * 1000)
    return () => {
      window.clearInterval(interval)
    }
  }, [lastUpdatedAt])

  useEffect(() => {
    setDocumentStatus(expiryLabel)
  }, [expiryLabel, setDocumentStatus])

  const headerActions = useMemo(() => [
    {
      id: 'temp-save',
      label: saving ? 'Saving…' : 'Save as document',
      onSelect: () => setSaveDialogOpen(true),
      disabled: saving || !hasContent,
      variant: 'primary' as const,
      icon: <Save className="h-4 w-4" />,
    },
    {
      id: 'temp-delete',
      label: 'Delete temporary',
      onSelect: () => setDeleteDialogOpen(true),
      disabled: saving,
      variant: 'outline' as const,
      icon: <Trash2 className="h-4 w-4" />,
    },
  ], [saving, hasContent])

  useEffect(() => {
    setDocumentActions(headerActions)
    return () => {
      setDocumentActions([])
    }
  }, [headerActions, setDocumentActions])

  useEffect(() => {
    return () => {
      setSaveDialogOpen(false)
      setDeleteDialogOpen(false)
    }
  }, [])

  const suggestedTitle = useMemo(
    () => deriveTitleSuggestion(getContentSnapshot()),
    [getContentSnapshot, lastUpdatedAt],
  )

  const handleSave = useCallback(async (title: string) => {
    const snapshot = getContentSnapshot()
    if (!snapshot.trim()) {
      toast.info('Temporary document is empty')
      return
    }
    setSaving(true)
    try {
      const created = await createDocument({ title: title.trim() || 'Untitled', parent_id: null })
      await updateDocumentContent({ id: created.id, content: snapshot })
      toast.success('Temporary document saved')
      setSaveDialogOpen(false)
      await removeEntry()
      navigate({ to: '/document/$id', params: { id: created.id } })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save document'
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }, [getContentSnapshot, removeEntry, navigate])

  const handleDeleteTemporary = useCallback(async () => {
    await removeEntry()
    setDeleteDialogOpen(false)
    navigate({ to: '/dashboard', replace: true })
  }, [removeEntry, navigate])

  const editorReady = status === 'ready' && doc && awareness
  const overlayLabel = error ?? 'Preparing scratchpad…'
  return (
    <div className="flex h-full flex-1 flex-col gap-4">
      <div className="relative flex-1 min-h-0 rounded-3xl border border-border/60 bg-background/95 shadow-lg">
        {!editorReady && <EditorOverlay label={overlayLabel} />}
        {editorReady && (
          <MarkdownEditor
            key={tempId}
            doc={doc}
            awareness={awareness}
            connected={false}
            initialView="split"
            documentId={tempId}
            readOnly={false}
          />
        )}
      </div>

      <SaveTemporaryDialog
        open={saveDialogOpen}
        onOpenChange={setSaveDialogOpen}
        pending={saving}
        initialTitle={suggestedTitle}
        onSubmit={handleSave}
      />

      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Delete temporary note?"
        description="This removes the temporary document from this browser. This cannot be undone."
        confirmText="Delete"
        onConfirm={() => { void handleDeleteTemporary() }}
      />
    </div>
  )
}

function SaveTemporaryDialog({ open, onOpenChange, onSubmit, pending, initialTitle }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (title: string) => void | Promise<void>
  pending: boolean
  initialTitle: string
}) {
  const [title, setTitle] = useState(initialTitle)

  useEffect(() => {
    if (open) {
      setTitle(initialTitle)
    }
  }, [open, initialTitle])

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    onSubmit(title.trim() || initialTitle)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Save as new document</DialogTitle>
          <DialogDescription>We will create a regular document and copy your temporary content into it.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="temp-doc-title">Title</Label>
            <Input
              id="temp-doc-title"
              placeholder="Untitled"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? 'Saving…' : 'Save & open'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function deriveTitleSuggestion(content: string) {
  const lines = content.split(/\r?\n/)
  const first = lines.find((line) => line.trim().length > 0)?.trim()
  if (!first) return 'Temporary note'
  return first.replace(/^#+\s*/, '').slice(0, 80) || 'Temporary note'
}

function formatExpiryLabel(lastUpdatedAt: number | null) {
  if (!lastUpdatedAt) return 'Expires in 24 hours'
  const expiresAt = lastUpdatedAt + TEMPORARY_DOCUMENT_TTL_MS
  const remainingMs = expiresAt - Date.now()
  if (remainingMs <= 0) return 'Expired — content will clear soon'
  const hours = Math.floor(remainingMs / (60 * 60 * 1000))
  const minutes = Math.floor((remainingMs % (60 * 60 * 1000)) / (60 * 1000))
  if (hours <= 0) {
    return `Expires in ${minutes} min`
  }
  return `Expires in ${hours}h ${minutes.toString().padStart(2, '0')}m`
}
