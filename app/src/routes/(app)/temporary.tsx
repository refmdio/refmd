import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { Clock, NotebookPen, RefreshCcw, Sparkles, Trash2 } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { toast } from 'sonner'

import { Button } from '@/shared/ui/button'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { appBeforeLoadGuard, useAuthContext } from '@/features/auth'
import { EditorOverlay, MarkdownEditor } from '@/features/edit-document'
import { useTemporaryDocument } from '@/features/temporary-document'

import { createDocument, updateDocumentContent } from '@/entities/document'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

import { useRealtime } from '@/processes/collaboration'

export const Route = createFileRoute('/(app)/temporary')({
  staticData: { layout: 'app' },
  beforeLoad: appBeforeLoadGuard,
  pendingComponent: () => <RoutePending label="Preparing temporary document…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: TemporaryDocumentPage,
})

function TemporaryDocumentPage() {
  const navigate = useNavigate()
  const { user } = useAuthContext()
  const { setDocumentTitle, setDocumentBadge, setDocumentStatus, setDocumentActions, setShowEditorFeatures, setDocumentId } = useRealtime()
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [clearDialogOpen, setClearDialogOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const tempDoc = useTemporaryDocument({ user: user ? { id: user.id, name: user.name } : undefined })
  const { doc, awareness, status, error, hasContent, lastUpdatedAt, clear, getContentSnapshot, contentLength } = tempDoc

  useEffect(() => {
    setDocumentTitle('Temporary document')
    setDocumentBadge('Local only')
    setDocumentStatus('Auto-saved to this browser. Cleared after 24 hours of inactivity.')
    setDocumentId(undefined)
    setShowEditorFeatures(true)
    return () => {
      setDocumentTitle(undefined)
      setDocumentBadge(undefined)
      setDocumentStatus(undefined)
      setDocumentId(undefined)
      setShowEditorFeatures(false)
    }
  }, [setDocumentTitle, setDocumentBadge, setDocumentStatus, setShowEditorFeatures, setDocumentId])

  const headerActions = useMemo(() => [
    {
      id: 'temp-save',
      label: saving ? 'Saving…' : 'Save as document',
      onSelect: () => setSaveDialogOpen(true),
      disabled: saving || !hasContent,
      variant: 'primary' as const,
    },
    {
      id: 'temp-clear',
      label: 'Clear',
      onSelect: () => {
        if (hasContent) setClearDialogOpen(true)
        else void clear()
      },
      disabled: !hasContent,
      variant: 'outline' as const,
    },
  ], [saving, hasContent, clear])

  useEffect(() => {
    setDocumentActions(headerActions)
    return () => {
      setDocumentActions([])
    }
  }, [headerActions, setDocumentActions])

  useEffect(() => {
    if (!hasContent) return
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', handler)
    return () => {
      window.removeEventListener('beforeunload', handler)
    }
  }, [hasContent])

  const suggestedTitle = useMemo(() => deriveTitleSuggestion(getContentSnapshot()), [getContentSnapshot, contentLength])

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
      await clear()
      navigate({ to: '/document/$id', params: { id: created.id } })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save document'
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }, [getContentSnapshot, clear, navigate])

  const editorReady = status === 'ready' && doc && awareness
  const overlayLabel = error ?? 'Preparing scratchpad…'
  const lastSavedLabel = formatLastSaved(lastUpdatedAt)

  return (
    <div className="flex h-full flex-1 flex-col gap-4">
      <section className="rounded-3xl border border-border/60 bg-background/95 px-4 py-4 shadow-sm backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-5 sm:py-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.25em] text-muted-foreground/70">
              <Sparkles className="h-3.5 w-3.5" />
              <span>Temporary</span>
            </div>
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Temporary document</h1>
              <p className="text-sm text-muted-foreground">Draft quickly without creating a document. Stored only on this browser.</p>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground/80">
              <span className="inline-flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5" />
                {lastSavedLabel}
              </span>
              <span className="inline-flex items-center gap-1.5">
                <NotebookPen className="h-3.5 w-3.5" />
                {hasContent ? `${contentLength} chars` : 'Empty note'}
              </span>
              <span className="inline-flex items-center gap-1.5">
                <RefreshCcw className="h-3.5 w-3.5" />
                Clears after 24h of inactivity
              </span>
            </div>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button variant="outline" onClick={() => (hasContent ? setClearDialogOpen(true) : void clear())} disabled={!hasContent}>
              <Trash2 className="mr-2 h-4 w-4" />
              Clear
            </Button>
            <Button onClick={() => setSaveDialogOpen(true)} disabled={!hasContent || saving}>
              <Sparkles className="mr-2 h-4 w-4" />
              {saving ? 'Saving…' : 'Save as document'}
            </Button>
          </div>
        </div>
      </section>

      <div className="relative flex-1 min-h-0 rounded-3xl border border-border/60 bg-background/95 shadow-lg">
        {!editorReady && <EditorOverlay label={overlayLabel} />}
        {editorReady && (
          <MarkdownEditor
            key="temporary-editor"
            doc={doc}
            awareness={awareness}
            connected={false}
            initialView="split"
            documentId="temporary-local"
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
        open={clearDialogOpen}
        onOpenChange={setClearDialogOpen}
        title="Clear temporary document?"
        description="This removes everything stored locally for this temporary document."
        confirmText="Clear"
        onConfirm={() => { void clear() }}
      />
    </div>
  )
}

type SaveDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (title: string) => void | Promise<void>
  pending: boolean
  initialTitle: string
}

function SaveTemporaryDialog({ open, onOpenChange, onSubmit, pending, initialTitle }: SaveDialogProps) {
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

function formatLastSaved(timestamp: number | null) {
  if (!timestamp) return 'Not saved in this session yet'
  const delta = Date.now() - timestamp
  if (delta < 60 * 1000) return 'Saved just now'
  if (delta < 60 * 60 * 1000) {
    const minutes = Math.floor(delta / (60 * 1000))
    return `Saved ${minutes} minute${minutes === 1 ? '' : 's'} ago`
  }
  if (delta < 24 * 60 * 60 * 1000) {
    const hours = Math.floor(delta / (60 * 60 * 1000))
    return `Saved ${hours} hour${hours === 1 ? '' : 's'} ago`
  }
  const date = new Date(timestamp)
  return `Saved on ${date.toLocaleDateString()} ${date.toLocaleTimeString()}`
}
