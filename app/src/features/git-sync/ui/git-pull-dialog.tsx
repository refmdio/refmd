import { Link } from '@tanstack/react-router'
import { AlertTriangle, ExternalLink, Loader2 } from 'lucide-react'

import type { GitPullConflictItem } from '@/shared/api'
import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  conflicts: GitPullConflictItem[]
  isLoading: boolean
  onRetry?: () => void
  emptyWarning?: boolean
  sessionId?: string | null
}

export default function GitPullDialog({ open, onOpenChange, conflicts, isLoading, onRetry, emptyWarning, sessionId }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('max-w-2xl', overlayPanelClass)}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Resolve conflicts
          </DialogTitle>
          <DialogDescription>
            Remote is ahead. Choose whether to keep your version or the remote version for each file, then apply.
          </DialogDescription>
          {sessionId ? (
            <div className="mt-2 text-xs text-muted-foreground">
              Session ID: <span className="font-mono text-foreground">{sessionId}</span>
            </div>
          ) : null}
        </DialogHeader>

        <div className="max-h-[50vh] space-y-3 overflow-auto pr-1">
          {isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>Loading conflicts…</span>
            </div>
          ) : conflicts.length === 0 ? (
            <div className="flex items-center justify-between gap-3">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">
                  {emptyWarning
                    ? 'Server reported conflicts but returned no list.'
                    : 'No conflicts reported.'}
                </p>
                {emptyWarning ? (
                  <p className="text-xs text-muted-foreground">
                    Retry the pull to attempt fetching the conflict list. If it persists, check Git server logs.
                  </p>
                ) : null}
              </div>
              {onRetry ? (
                <Button size="sm" variant="outline" onClick={onRetry}>
                  Retry pull
                </Button>
              ) : null}
            </div>
          ) : (
            conflicts.map((conflict) => {
              const docId = conflict.document_id
              const conflictLink = docId ? { id: docId } : null
              return (
                <div
                  key={conflict.path}
                  className="rounded-lg border border-border/60 bg-muted/30 p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="font-medium text-foreground break-all">{conflict.path}</div>
                    {conflictLink ? (
                      <Button asChild size="sm" variant="outline">
                        <Link
                          to="/document/$id"
                          params={conflictLink}
                          search={{ conflict: '' }}
                          onClick={() => onOpenChange(false)}
                        >
                          Open
                          <ExternalLink className="ml-1 h-4 w-4" />
                        </Link>
                      </Button>
                    ) : (
                      <Button size="sm" variant="ghost" disabled>
                        No document link
                      </Button>
                    )}
                  </div>
                  {!conflict.is_binary ? (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Text conflict. Open the document to resolve hunks, then apply merge.
                    </p>
                  ) : (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Binary file. Only full-file choice is supported.
                    </p>
                  )}
                </div>
              )
            })
          )}
        </div>

        <DialogFooter>
          <Button
            onClick={() => onOpenChange(false)}
            variant="ghost"
          >
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
