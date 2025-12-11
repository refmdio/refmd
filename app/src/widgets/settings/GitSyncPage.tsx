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

import {
  createOrUpdateConfig,
  deinitRepository,
  getConfig,
  getStatus,
  initRepository,
  importRepository,
} from '@/entities/git'

import { settingsNavItems } from '@/features/settings/nav'

import { SettingsShell } from './SettingsShell'

type RemoteCheck = { ok: boolean; message: string; reason?: string | null } | null

export default function GitSyncPage() {
  const qc = useQueryClient()
  const { data: config } = useQuery({ queryKey: ['git-config'], queryFn: () => getConfig(), retry: false })
  const { data: status } = useQuery({ queryKey: ['git-status'], queryFn: () => getStatus(), retry: false })

  const [repositoryUrl, setRepositoryUrl] = React.useState('')
  const [branchName, setBranchName] = React.useState('main')
  const [authType, setAuthType] = React.useState<'ssh' | 'token'>('token')
  const [token, setToken] = React.useState('')
  const [privateKey, setPrivateKey] = React.useState('')
  const [lastCheck, setLastCheck] = React.useState<RemoteCheck>(null)
  const lastSecretRef = React.useRef<{ token?: string; private_key?: string }>({})
  const autoSync = false

  React.useEffect(() => {
    if (config) {
      setRepositoryUrl(config.repository_url || '')
      setBranchName(config.branch_name || 'main')
      setAuthType(config.auth_type === 'ssh' ? 'ssh' : 'token')
      setToken('')
      setPrivateKey('')
      setLastCheck((config as any).remote_check ?? null)
    }
  }, [config])

  const resolveAuthData = React.useCallback(() => {
    if (authType === 'token') {
      const resolved = token.trim() || lastSecretRef.current.token
      if (!resolved) {
        throw new Error('Personal access token is required to save.')
      }
      lastSecretRef.current = { token: resolved }
      return { token: resolved }
    }
    const resolved = privateKey.trim() || lastSecretRef.current.private_key
    if (!resolved) {
      throw new Error('SSH private key is required to save.')
    }
    lastSecretRef.current = { private_key: resolved }
    return { private_key: resolved }
  }, [authType, privateKey, token])

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!repositoryUrl.trim()) throw new Error('Repository URL is required')
      const auth_data = resolveAuthData()
      return createOrUpdateConfig({
        requestBody: {
          repository_url: repositoryUrl.trim(),
          branch_name: branchName.trim() || 'main',
          auth_type: authType,
          auth_data,
          auto_sync: autoSync,
        },
      })
    },
    onSuccess: (data: any) => {
      toast.success('Git settings saved')
      if (data?.remote_check) setLastCheck(data.remote_check)
      qc.invalidateQueries({ queryKey: ['git-config'] })
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
    onError: (e: any) => {
      toast.error(`Failed to save settings: ${e?.message || e}`)
    },
  })

  const importMutation = useMutation({
    mutationFn: async () => {
      if (!repositoryUrl.trim()) throw new Error('Repository URL is required')
      const auth_data = resolveAuthData()
      return importRepository({
        requestBody: {
          repository_url: repositoryUrl.trim(),
          branch_name: branchName.trim() || 'main',
          auth_type: authType,
          auth_data,
          auto_sync: autoSync,
        },
      })
    },
    onSuccess: (data: any) => {
      const msg = data?.message || 'Imported from Git'
      const docs = data?.docs_created ?? 0
      const attachments = data?.attachments_created ?? 0
      const extra =
        docs || attachments ? ` (${docs} docs, ${attachments} attachments)` : ''
      toast.success(`${msg}${extra}`)
      qc.invalidateQueries({ queryKey: ['git-status'] })
      qc.invalidateQueries({ queryKey: ['git-config'] })
    },
    onError: (e: any) => {
      const raw = e?.body?.message || e?.message || `${e}`
      toast.error(`Import failed: ${raw}`)
    },
  })

  const initMutation = useMutation({
    mutationFn: () => initRepository(),
    onSuccess: () => {
      toast.success('Git repository initialized')
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
    onError: (e: any) => toast.error(`Initialization failed: ${e?.message || e}`),
  })

  const deinitMutation = useMutation({
    mutationFn: () => deinitRepository(),
    onSuccess: () => {
      toast.success('Stopped using Git')
      qc.invalidateQueries({ queryKey: ['git-config'] })
      qc.invalidateQueries({ queryKey: ['git-status'] })
    },
    onError: (e: any) => {
      toast.error(`Failed to stop: ${e?.message || e}`)
    },
  })

  const repositoryInitialized = Boolean(status?.repository_initialized)
  const hasRemote = Boolean(status?.has_remote)
  const statusMessage = status?.last_sync_message || (repositoryInitialized ? 'Ready' : 'Not initialized')

  const renderRemoteCheck = () => {
    if (!lastCheck) return null
    const warning = !lastCheck.ok
    return (
      <Card className="border-border/60 p-4 shadow-sm bg-muted/40">
        <div className="flex items-start gap-3 text-sm">
          <ShieldCheck className={`h-4 w-4 ${warning ? 'text-destructive' : 'text-primary'}`} />
          <div className="space-y-1 text-muted-foreground">
            <p className="text-foreground font-medium">Remote check</p>
            <p>{lastCheck.message}</p>
          </div>
        </div>
      </Card>
    )
  }

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
                  disabled={initMutation.isPending}
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
                <p className="text-foreground font-semibold">{branchName || '—'}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-2xl border border-border/60 bg-muted/30 px-4 py-3">
              <ShieldCheck className="h-4 w-4 text-primary" />
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Auth</p>
                <p className="text-foreground font-semibold">{authType.toUpperCase()}</p>
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
              <p className="text-sm text-muted-foreground">Save your repository details and authentication. Tokens/keys are encrypted and never returned.</p>
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
                    variant={authType === 'token' ? 'default' : 'outline'}
                    onClick={() => setAuthType('token')}
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

            {authType === 'token' ? (
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
                <Input
                  type="password"
                  placeholder="-----BEGIN PRIVATE KEY-----"
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Reuses the last key you entered on this page. After a reload, enter it again before saving.
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

        {renderRemoteCheck()}
      </div>
    </SettingsShell>
  )
}
