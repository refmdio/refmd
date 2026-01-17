import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { GitBranch, GitCommit, ShieldCheck } from 'lucide-react'
import React from 'react'
import { toast } from 'sonner'

import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Separator } from '@/shared/ui/separator'
import { Textarea } from '@/shared/ui/textarea'

import { useAuthContext } from '@/features/auth'
import {
  saveGitCredentials,
  loadGitCredentials,
  hasGitCredentials,
  deleteGitCredentials,
  getGitStatus,
  importFromGit,
  initGitRepository,
  clearImportedRepository,
  type GitCredentials,
} from '@/features/git-sync'
import { settingsNavItems } from '@/features/settings/nav'

import { SettingsShell } from './SettingsShell'

export default function GitSyncPage() {
  const qc = useQueryClient()
  const { activeWorkspaceId } = useAuthContext()

  // Load credentials from server (E2EE decrypted)
  const { data: credentials } = useQuery({
    queryKey: ['git-credentials', activeWorkspaceId],
    queryFn: () => activeWorkspaceId ? loadGitCredentials(activeWorkspaceId) : null,
    enabled: !!activeWorkspaceId,
    retry: false,
  })

  // Check if credentials exist
  const { data: hasCredentialsData } = useQuery({
    queryKey: ['git-has-credentials', activeWorkspaceId],
    queryFn: () => hasGitCredentials(),
    enabled: !!activeWorkspaceId,
    retry: false,
  })

  // Get git status (client-side)
  const { data: status } = useQuery({
    queryKey: ['git-status', activeWorkspaceId],
    queryFn: () => activeWorkspaceId ? getGitStatus(activeWorkspaceId) : null,
    enabled: !!activeWorkspaceId && !!hasCredentialsData,
    retry: false,
  })

  const [repositoryUrl, setRepositoryUrl] = React.useState('')
  const [branchName, setBranchName] = React.useState('main')
  const [authType, setAuthType] = React.useState<'ssh' | 'https-pat'>('https-pat')
  const [token, setToken] = React.useState('')
  const [privateKey, setPrivateKey] = React.useState('')
  const [passphrase, setPassphrase] = React.useState('')
  const lastSecretRef = React.useRef<{ token?: string; privateKey?: string; passphrase?: string }>({})

  React.useEffect(() => {
    if (credentials) {
      setRepositoryUrl(credentials.repositoryUrl || '')
      setBranchName(credentials.branchName || 'main')
      setAuthType(credentials.authType === 'ssh' ? 'ssh' : 'https-pat')
      // Don't set sensitive fields - they're still encrypted on server
      setToken('')
      setPrivateKey('')
      setPassphrase('')
    }
  }, [credentials])

  const resolveAuthData = React.useCallback((): Partial<GitCredentials> => {
    if (authType === 'https-pat') {
      const resolved = token.trim() || lastSecretRef.current.token
      if (!resolved) {
        throw new Error('Personal access token is required to save.')
      }
      lastSecretRef.current = { token: resolved }
      return { token: resolved }
    }
    const resolvedKey = privateKey.trim() || lastSecretRef.current.privateKey
    if (!resolvedKey) {
      throw new Error('SSH private key is required to save.')
    }
    const resolvedPass = passphrase.trim() || lastSecretRef.current.passphrase
    lastSecretRef.current = { privateKey: resolvedKey, passphrase: resolvedPass }
    return resolvedPass ? { privateKey: resolvedKey, passphrase: resolvedPass } : { privateKey: resolvedKey }
  }, [authType, privateKey, token, passphrase])

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!activeWorkspaceId) throw new Error('No workspace selected')
      if (!repositoryUrl.trim()) throw new Error('Repository URL is required')
      const authData = resolveAuthData()
      const creds: GitCredentials = {
        repositoryUrl: repositoryUrl.trim(),
        branchName: branchName.trim() || 'main',
        authType,
        ...authData,
      }
      await saveGitCredentials(activeWorkspaceId, creds)
    },
    onSuccess: () => {
      toast.success('Git settings saved')
      qc.invalidateQueries({ queryKey: ['git-credentials', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-has-credentials', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
    },
    onError: (e: Error) => {
      toast.error(`Failed to save settings: ${e.message}`)
    },
  })

  const importMutation = useMutation({
    mutationFn: async () => {
      if (!activeWorkspaceId) throw new Error('No workspace selected')
      if (!repositoryUrl.trim()) throw new Error('Repository URL is required')
      const authData = resolveAuthData()
      const creds: GitCredentials = {
        repositoryUrl: repositoryUrl.trim(),
        branchName: branchName.trim() || 'main',
        authType,
        ...authData,
      }
      // Save credentials first
      await saveGitCredentials(activeWorkspaceId, creds)
      // Then import
      return importFromGit(activeWorkspaceId, repositoryUrl.trim(), creds)
    },
    onSuccess: (result) => {
      const msg = result.message
      const docs = result.docsCreated ?? 0
      const attachments = result.attachmentsFound ?? 0
      const extra = docs || attachments ? ` (${docs} docs, ${attachments} attachments)` : ''
      toast.success(`${msg}${extra}`)
      qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-credentials', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-has-credentials', activeWorkspaceId] })
      // Refresh file tree to show imported documents
      qc.invalidateQueries({ queryKey: ['documents'] })
    },
    onError: (e: Error) => {
      toast.error(`Import failed: ${e.message}`)
    },
  })

  const initMutation = useMutation({
    mutationFn: async () => {
      if (!activeWorkspaceId) throw new Error('No workspace selected')
      if (!repositoryUrl.trim()) throw new Error('Repository URL is required')
      const authData = resolveAuthData()
      const creds: GitCredentials = {
        repositoryUrl: repositoryUrl.trim(),
        branchName: branchName.trim() || 'main',
        authType,
        ...authData,
      }
      // Save credentials first
      await saveGitCredentials(activeWorkspaceId, creds)
      // Then initialize (clone)
      return initGitRepository(activeWorkspaceId, repositoryUrl.trim(), creds)
    },
    onSuccess: (result) => {
      if (result.success) {
        toast.success('Git repository initialized')
      } else {
        toast.error(result.message)
      }
      qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-credentials', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-has-credentials', activeWorkspaceId] })
    },
    onError: (e: Error) => toast.error(`Initialization failed: ${e.message}`),
  })

  const deinitMutation = useMutation({
    mutationFn: async () => {
      if (!activeWorkspaceId) throw new Error('No workspace selected')
      // Clear local repository data
      await clearImportedRepository(activeWorkspaceId)
      // Delete credentials from server
      await deleteGitCredentials()
    },
    onSuccess: () => {
      toast.success('Stopped using Git')
      qc.invalidateQueries({ queryKey: ['git-credentials', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-has-credentials', activeWorkspaceId] })
      qc.invalidateQueries({ queryKey: ['git-status', activeWorkspaceId] })
    },
    onError: (e: Error) => {
      toast.error(`Failed to stop: ${e.message}`)
    },
  })

  const repositoryInitialized = Boolean(status?.initialized)
  const hasRemote = Boolean(hasCredentialsData)
  const statusMessage = repositoryInitialized ? 'Ready' : 'Not initialized'

  return (
    <SettingsShell
      header={{
        eyebrow: 'Sync',
        title: 'Git Sync',
        description: 'Enable syncing to a repository and manage authentication.',
      }}
      navItems={settingsNavItems}
    >
      <div className="space-y-6">
        <Card className="border-border/60 p-6 shadow-sm">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                <GitCommit className="h-4 w-4 text-primary" />
                <span>Status</span>
              </div>
              <p className="text-lg font-semibold text-foreground">{repositoryInitialized ? 'Enabled' : 'Disabled'}</p>
              <p className="text-sm text-muted-foreground">{statusMessage}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {repositoryInitialized ? (
                <Button
                  variant="outline"
                  onClick={() => deinitMutation.mutate()}
                  disabled={deinitMutation.isPending}
                  className="rounded-full"
                >
                  {deinitMutation.isPending ? 'Stopping…' : 'Stop using Git'}
                </Button>
              ) : (
                <Button
                  onClick={() => initMutation.mutate()}
                  disabled={initMutation.isPending || !repositoryUrl.trim()}
                  className="rounded-full"
                >
                  {initMutation.isPending ? 'Enabling…' : 'Enable Git Sync'}
                </Button>
              )}
            </div>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3 text-sm text-muted-foreground">
            <div className="flex items-center gap-2 rounded-2xl border border-border/60 bg-muted/30 px-4 py-3">
              <GitBranch className="h-4 w-4 text-primary" />
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Branch</p>
                <p className="text-foreground font-semibold">{status?.branch || branchName || '—'}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-2xl border border-border/60 bg-muted/30 px-4 py-3">
              <ShieldCheck className="h-4 w-4 text-primary" />
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Auth</p>
                <p className="text-foreground font-semibold">{authType === 'ssh' ? 'SSH' : 'TOKEN'}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-2xl border border-border/60 bg-muted/30 px-4 py-3">
              <GitCommit className="h-4 w-4 text-primary" />
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Remote</p>
                <p className="text-foreground font-semibold">{hasRemote ? 'Connected' : 'Not connected'}</p>
              </div>
            </div>
          </div>
        </Card>

        <Card className="border-border/60 p-6 shadow-sm">
          <div className="space-y-6">
            <div className="space-y-2">
              <Badge variant="secondary" className="rounded-full px-3 py-1 text-[11px] uppercase tracking-wide">Repository</Badge>
              <p className="text-sm text-muted-foreground">Save your repository details and authentication. Credentials are encrypted with your workspace key.</p>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="repo">Repository URL</Label>
                <Input
                  id="repo"
                  type="url"
                  placeholder="https://github.com/user/repo.git"
                  value={repositoryUrl}
                  onChange={(e) => setRepositoryUrl(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="branch">Branch name</Label>
                <Input
                  id="branch"
                  value={branchName}
                  onChange={(e) => setBranchName(e.target.value)}
                  placeholder="main"
                />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Auth type</Label>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant={authType === 'https-pat' ? 'default' : 'outline'}
                    onClick={() => setAuthType('https-pat')}
                    className="flex-1"
                  >
                    Token
                  </Button>
                  <Button
                    type="button"
                    variant={authType === 'ssh' ? 'default' : 'outline'}
                    onClick={() => setAuthType('ssh')}
                    className="flex-1"
                  >
                    SSH
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">Leave the secret blank to keep the existing one.</p>
              </div>
            </div>

            {authType === 'https-pat' ? (
              <div className="space-y-2">
                <Label>Personal access token</Label>
                <Input
                  type="password"
                  placeholder="ghp_..."
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Reuses the last token you entered on this page. After a reload, enter it again before saving.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <Label>SSH private key</Label>
                <Textarea
                  placeholder={`-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----`}
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  rows={6}
                  className="font-mono"
                />
                <Label>Passphrase (if encrypted)</Label>
                <Input
                  type="password"
                  placeholder="Leave blank if none"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Reuses the last key/passphrase you entered on this page. After a reload, enter them again before saving.
                </p>
              </div>
            )}

            <Separator />

            <p className="text-xs text-muted-foreground">
              Auto sync is off. Use Pull to fetch remote changes and Sync to push manually. Use Import to populate this workspace from the remote repository.
            </p>

            <div className="flex flex-wrap items-center gap-3">
              <Button
                onClick={() => saveMutation.mutate()}
                disabled={saveMutation.isPending || !repositoryUrl.trim()}
                className="rounded-full"
              >
                {saveMutation.isPending ? 'Saving…' : 'Save settings'}
              </Button>
              <Button
                variant="outline"
                onClick={() => importMutation.mutate()}
                disabled={
                  importMutation.isPending ||
                  saveMutation.isPending ||
                  !repositoryUrl.trim()
                }
                className="rounded-full"
              >
                {importMutation.isPending ? 'Importing…' : 'Import from Git'}
              </Button>
            </div>
          </div>
        </Card>
      </div>
    </SettingsShell>
  )
}
