import { AlertTriangle, Loader2 } from 'lucide-react'
import React from 'react'

import type { GitPullConflictItem, GitPullResolution } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  conflicts: GitPullConflictItem[]
  isLoading: boolean
  onResolve: (resolutions: GitPullResolution[]) => void
  onRetry?: () => void
  emptyWarning?: boolean
  sessionId?: string | null
}

export default function GitPullDialog({ open, onOpenChange, conflicts, isLoading, onResolve, onRetry, emptyWarning, sessionId }: Props) {
  const [choices, setChoices] = React.useState<Record<string, GitPullResolution['choice']>>({})

  React.useEffect(() => {
    if (!open) {
      setChoices({})
    }
  }, [open])

  const allResolved = conflicts.length === 0 || conflicts.every((c) => choices[c.path])

  const handleSubmit = () => {
    if (!conflicts.length) {
      onOpenChange(false)
      return
    }
    const resolutions: GitPullResolution[] = conflicts
      .map((c) => {
        const choice = choices[c.path]
        if (!choice) return null
        return { path: c.path, choice }
      })
      .filter(Boolean) as GitPullResolution[]
    onResolve(resolutions)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
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
              const choice = choices[conflict.path]
              return (
                <div
                  key={conflict.path}
                  className="rounded-lg border border-border/60 bg-muted/30 p-3"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-medium text-foreground break-all">{conflict.path}</div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant={choice === 'ours' ? 'default' : 'outline'}
                        onClick={() =>
                          setChoices((prev) => ({
                            ...prev,
                            [conflict.path]: 'ours',
                          }))
                        }
                      >
                        Keep mine
                      </Button>
                      <Button
                        size="sm"
                        variant={choice === 'theirs' ? 'default' : 'outline'}
                        onClick={() =>
                          setChoices((prev) => ({
                            ...prev,
                            [conflict.path]: 'theirs',
                          }))
                        }
                      >
                        Take remote
                      </Button>
                    </div>
                  </div>
                  {!conflict.is_binary ? (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Text file. Choose the side to keep.
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
          <Button
            onClick={handleSubmit}
            disabled={!allResolved || isLoading || conflicts.length === 0}
          >
            {isLoading ? 'Applying…' : 'Apply resolutions'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
