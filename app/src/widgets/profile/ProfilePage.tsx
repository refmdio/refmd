import { Link } from '@tanstack/react-router'
import { ArrowRight, Copy, Globe, Key, Loader2, Mail, Shield, Trash2, Users } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { toast } from 'sonner'

import { Avatar, AvatarFallback } from '@/shared/ui/avatar'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'
import ConfirmDialog from '@/shared/ui/confirm-dialog'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'

import { useCreateApiToken, useApiTokens, useRevokeApiToken } from '@/entities/api-token'
import { useUserSessions, useRevokeSession } from '@/entities/user'

import { useAuthContext } from '@/features/auth'

const PUBLIC_PROFILE_URL = (slug?: string | null, fallbackName?: string | null) => {
  if (slug && slug.trim().length > 0) {
    return `/w/${encodeURIComponent(slug)}`
  }
  return `/u/${encodeURIComponent(fallbackName ?? '')}/`
}

export default function ProfilePage() {
  const { user, deleteAccount, activeWorkspace, activeWorkspaceId } = useAuthContext()
  const displayName = user?.name || 'User'
  const initials = displayName.slice(0, 1).toUpperCase()
  const email = user?.email || 'No email attached'
  const publicUrl = PUBLIC_PROFILE_URL(activeWorkspace?.slug, user?.name)

  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [newTokenName, setNewTokenName] = useState('')
  const [generatedToken, setGeneratedToken] = useState<string | null>(null)
  const [revokeDialogFor, setRevokeDialogFor] = useState<{ id: string; name: string } | null>(null)
  const [sessionsDialogOpen, setSessionsDialogOpen] = useState(false)

  const tokensQuery = useApiTokens({ workspaceId: activeWorkspaceId })
  const tokens = tokensQuery.data ?? []
  const activeTokens = useMemo(() => tokens.filter((token) => !token.revoked_at), [tokens])

  const createTokenMutation = useCreateApiToken({
    workspaceId: activeWorkspaceId,
    onSuccess: (data) => {
      setGeneratedToken(data.token)
      setNewTokenName('')
      toast.success('API token issued')
    },
    onError: () => {
      toast.error('Failed to create API token')
    },
  })

  const revokeTokenMutation = useRevokeApiToken({
    workspaceId: activeWorkspaceId,
    onSuccess: () => {
      toast.success('API token revoked')
      setRevokeDialogFor(null)
    },
    onError: () => {
      toast.error('Failed to revoke API token')
    },
  })

  const handleGenerateToken = useCallback(() => {
    const trimmed = newTokenName.trim()
    setGeneratedToken(null)
    createTokenMutation.mutate(trimmed.length > 0 ? { name: trimmed } : {})
  }, [createTokenMutation, newTokenName])

  const handleConfirmRevoke = useCallback(() => {
    if (!revokeDialogFor) return
    revokeTokenMutation.mutate(revokeDialogFor.id)
  }, [revokeDialogFor, revokeTokenMutation])

  const sessionsQuery = useUserSessions({ enabled: sessionsDialogOpen })
  const sessions = sessionsQuery.data ?? []
  const revokeSessionMutation = useRevokeSession({
    onSuccess: () => {
      toast.success('Session revoked')
    },
    onError: () => {
      toast.error('Failed to revoke session')
    },
  })

  const handleRevokeSession = useCallback(
    (sessionId: string) => {
      revokeSessionMutation.mutate(sessionId)
    },
    [revokeSessionMutation],
  )

  const formatTimestamp = useCallback((value?: string | null) => {
    if (!value) return 'Never used'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleString()
  }, [])

  const handleCopyToken = useCallback((value: string) => {
    if (!value) return
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard
        .writeText(value)
        .then(() => toast.success('Copied token to clipboard'))
        .catch(() => toast.error('Failed to copy token'))
    } else {
      toast.error('Clipboard is not available')
    }
  }, [])

  const performAccountDeletion = useCallback(async () => {
    setIsDeleting(true)
    try {
      await deleteAccount()
      toast.success('Your account has been deleted.')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to delete account.'
      toast.error(message)
      setIsDeleting(false)
      setDeleteDialogOpen(true)
    }
  }, [deleteAccount])

  const handleConfirmDelete = useCallback(() => {
    void performAccountDeletion()
  }, [performAccountDeletion])

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-8 px-4 pb-16 pt-10 sm:px-6 md:px-8">
        <section className="rounded-3xl border border-border/60 p-6 shadow-lg backdrop-blur md:p-8">
          <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <Avatar className="h-16 w-16 text-lg">
                <AvatarFallback>{initials}</AvatarFallback>
              </Avatar>
              <div className="space-y-2">
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <h1 className="text-2xl font-semibold tracking-tight text-foreground">{displayName}</h1>
                    <Badge variant="secondary" className="rounded-full px-3 py-1 text-xs uppercase tracking-wide">
                      Workspace Owner
                    </Badge>
                  </div>
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Mail className="h-4 w-4" />
                    {email}
                  </p>
                </div>
                <p className="max-w-xl text-sm text-muted-foreground">
                  Manage how you appear across shared and public RefMD spaces. Update your public profile to make it easier for collaborators to find you.
                </p>
              </div>
            </div>
            <Button asChild variant="outline" className="mt-4 inline-flex items-center gap-2 rounded-full px-4 md:mt-0">
              <a href={publicUrl} target="_blank" rel="noopener noreferrer">
                <Users className="h-4 w-4" />
                View public profile
                <ArrowRight className="h-4 w-4" />
              </a>
            </Button>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-2">
          <Card className="border-border/60 p-6 shadow-sm">
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-primary" />
              <div className="space-y-2">
                <h2 className="text-base font-semibold text-foreground">Account security</h2>
                <p className="text-sm text-muted-foreground">
                  Your account is protected by workspace authentication. Sign out from other devices to keep things secure.
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="rounded-full px-4"
                    onClick={() => setSessionsDialogOpen(true)}
                  >
                    Manage sessions
                  </Button>
                  <Button
                    variant="destructive"
                    size="sm"
                    className="rounded-full px-4"
                    onClick={() => setDeleteDialogOpen(true)}
                    disabled={isDeleting}
                  >
                    Delete account
                  </Button>
                </div>
              </div>
            </div>
          </Card>

          <Card className="border-border/60 p-6 shadow-sm">
            <div className="flex items-start gap-3">
              <Globe className="h-5 w-5 text-primary" />
              <div className="space-y-2">
                <h2 className="text-base font-semibold text-foreground">Public presence</h2>
                <p className="text-sm text-muted-foreground">
                  Configure which documents appear at your public URL and keep your published work up to date.
                </p>
                <Button asChild size="sm" className="rounded-full px-4">
                  <Link to="/visibility" className="inline-flex items-center gap-2">
                    Manage visibility
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              </div>
            </div>
          </Card>
        </section>

        <section className="space-y-4">
          <Card className="border-border/60 p-6 shadow-sm">
            <div className="flex items-start gap-3">
              <Key className="h-5 w-5 text-primary" />
              <div className="flex-1 space-y-4">
                <div className="space-y-2">
                  <h2 className="text-base font-semibold text-foreground">API tokens</h2>
                  <p className="text-sm text-muted-foreground">
                    Generate long-lived API tokens for CLI tools or MCP integrations. Tokens are shown only once—store them securely.
                  </p>
                </div>
                <form
                  className="flex flex-col gap-3 sm:flex-row"
                  onSubmit={(event) => {
                    event.preventDefault()
                    handleGenerateToken()
                  }}
                >
                  <Input
                    value={newTokenName}
                    onChange={(event) => setNewTokenName(event.target.value)}
                    placeholder="Token label (optional)"
                    autoComplete="off"
                  />
                  <Button
                    type="submit"
                    className="shrink-0 sm:w-auto"
                    disabled={createTokenMutation.isPending}
                  >
                    {createTokenMutation.isPending ? 'Creating…' : 'Create token'}
                  </Button>
                </form>

                {generatedToken && (
                  <div className="rounded-md border border-dashed border-primary/40 bg-primary/5 p-4 text-sm">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="space-y-1">
                        <p className="font-medium text-primary">New token</p>
                        <p className="text-muted-foreground">
                          Copy this value now. You won&apos;t be able to see it again.
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <code className="rounded bg-background px-2 py-1 text-xs">{generatedToken}</code>
                        <Button
                          type="button"
                          variant="outline"
                          size="icon"
                          onClick={() => handleCopyToken(generatedToken)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                )}

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium text-foreground">Active tokens</h3>
                    {tokensQuery.isFetching && <span className="text-xs text-muted-foreground">Refreshing…</span>}
                  </div>
                  {tokensQuery.isError ? (
                    <p className="text-sm text-destructive">Failed to load tokens. Please try again.</p>
                  ) : activeTokens.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No API tokens yet.</p>
                  ) : (
                    <ul className="space-y-2">
                      {activeTokens.map((token) => (
                        <li
                          key={token.id}
                          className="flex flex-col gap-2 rounded-md border border-border/70 p-3 sm:flex-row sm:items-center sm:justify-between"
                        >
                          <div className="space-y-1">
                            <p className="font-medium text-sm text-foreground">{token.name}</p>
                            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                              <span>Created: {formatTimestamp(token.created_at)}</span>
                              <span>Last used: {formatTimestamp(token.last_used_at)}</span>
                              {token.revoked_at && <span>Revoked: {formatTimestamp(token.revoked_at)}</span>}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              onClick={() => setRevokeDialogFor({ id: token.id, name: token.name })}
                              disabled={revokeTokenMutation.isPending}
                              className="text-destructive hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          </Card>
        </section>
      </div>
      <Dialog open={sessionsDialogOpen} onOpenChange={setSessionsDialogOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Active sessions</DialogTitle>
            <DialogDescription>Sign out from browsers or devices you no longer use.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {sessionsQuery.isLoading ? (
              <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading sessions…
              </div>
            ) : sessions.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">No active sessions</p>
            ) : (
              <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
                {sessions.map((session) => {
                  const isPending =
                    revokeSessionMutation.isPending && revokeSessionMutation.variables === session.id
                  return (
                    <div key={session.id} className="flex items-start justify-between rounded-lg border border-border/60 p-3">
                      <div className="space-y-1 text-sm">
                        <p className="font-medium text-foreground">{session.user_agent || 'Unknown device'}</p>
                        <p className="text-xs text-muted-foreground">
                          Last active {formatTimestamp(session.last_seen_at)}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {session.ip_address ? `IP ${session.ip_address}` : 'IP unknown'}
                        </p>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <div className="flex flex-wrap justify-end gap-2">
                          {session.current && <Badge variant="secondary">Current</Badge>}
                          {session.remember_me && <Badge variant="outline">Remembered</Badge>}
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={session.current || isPending}
                          onClick={() => handleRevokeSession(session.id)}
                        >
                          {isPending ? 'Removing…' : 'Remove'}
                        </Button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title="Delete account"
        description="This will permanently remove your account, documents, and integrations. This action cannot be undone."
        confirmText="Delete"
        onConfirm={handleConfirmDelete}
      />
      <ConfirmDialog
        open={!!revokeDialogFor}
        onOpenChange={(open) => {
          if (!open) setRevokeDialogFor(null)
        }}
        title="Revoke token"
        description={
          revokeDialogFor ? `Revoke the token "${revokeDialogFor.name}"? This action cannot be undone.` : undefined
        }
        confirmText={revokeTokenMutation.isPending ? 'Revoking…' : 'Revoke'}
        onConfirm={handleConfirmRevoke}
        confirmDisabled={revokeTokenMutation.isPending}
      />
    </div>
  )
}
