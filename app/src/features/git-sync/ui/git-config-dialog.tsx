import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import React from 'react'
import { toast } from 'sonner'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Alert, AlertDescription } from '@/shared/ui/alert'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/shared/ui/select'

import { getConfig, getStatus, createOrUpdateConfig, deinitRepository } from '@/entities/git'

type Props = { open: boolean; onOpenChange: (open: boolean) => void }

export default function GitConfigDialog({ open, onOpenChange }: Props) {
  const qc = useQueryClient()
  const { data: existingConfig } = useQuery({
    queryKey: ['git-config'],
    queryFn: () => getConfig(),
    enabled: open,
    retry: false,
  })
  const { data: gitStatus } = useQuery({
    queryKey: ['git-status'],
    queryFn: () => getStatus(),
    enabled: open,
    retry: false,
  })

  const [repositoryUrl, setRepositoryUrl] = React.useState('')
  const [branchName, setBranchName] = React.useState('main')
  const [authType, setAuthType] = React.useState<'ssh'|'token'>('token')
  const [token, setToken] = React.useState('')
  const [privateKey, setPrivateKey] = React.useState('')
  const [autoSync, setAutoSync] = React.useState(true)
  const [lastCheck, setLastCheck] = React.useState<{ ok: boolean; message: string; reason?: string | null } | null>(null)

  React.useEffect(() => {
    if (existingConfig) {
      setRepositoryUrl(existingConfig.repository_url || '')
      setBranchName(existingConfig.branch_name || 'main')
      setAuthType(existingConfig.auth_type === 'ssh' ? 'ssh' : 'token')
      setToken('')
      setPrivateKey('')
      setAutoSync(existingConfig.auto_sync ?? true)
      setLastCheck(existingConfig.remote_check ?? null)
    }
  }, [existingConfig])

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!repositoryUrl.trim()) throw new Error('Repository URL is required')
      const auth_data = authType === 'token' ? { token } : { private_key: privateKey }
      return createOrUpdateConfig({ requestBody: { repository_url: repositoryUrl.trim(), branch_name: branchName.trim() || 'main', auth_type: authType, auth_data, auto_sync: autoSync } })
    },
    onSuccess: (data: any) => {
      toast.success('Git settings saved')
      if (data?.remote_check) setLastCheck(data.remote_check)
      qc.invalidateQueries({ queryKey: ['git-config'] })
      qc.invalidateQueries({ queryKey: ['git-status'] })
      onOpenChange(false)
    },
    onError: (e: any) => { toast.error(`Failed to save settings: ${e?.message || e}`) }
  })

  const deinitMutation = useMutation({
    mutationFn: () => deinitRepository(),
    onSuccess: () => { toast.success('Stopped using Git'); qc.invalidateQueries({ queryKey: ['git-status'] }) },
    onError: (e: any) => { toast.error(`Failed to stop: ${e?.message || e}`) }
  })

  const renderCheckMessage = () => {
    if (!lastCheck) return null
    if (lastCheck.reason === 'repo_not_found') {
      return 'Repository URL or branch was not found. Please check the URL/branch.'
    }
    if (lastCheck.reason === 'auth_required') {
      return 'Remote requires authentication/SSO approval. Please re-enter your token/SSH key and approve SSO if needed.'
    }
    return lastCheck.message
  }

  const checkMessage = renderCheckMessage()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('sm:max-w-[500px]', overlayPanelClass)}>
        <DialogHeader>
          <DialogTitle>Git Sync Settings</DialogTitle>
          <DialogDescription>Configure settings to sync documents with a Git repository.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="repo">Repository URL *</Label>
            <Input id="repo" type="url" placeholder="https://github.com/user/repo.git" value={repositoryUrl} onChange={(e)=>setRepositoryUrl(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="branch">Branch name</Label>
            <Input id="branch" value={branchName} onChange={(e)=>setBranchName(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-2">
              <Label>Auth Type</Label>
              <Select value={authType} onValueChange={(v)=>setAuthType(v as any)}>
                <SelectTrigger><SelectValue placeholder="Select" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="token">Token</SelectItem>
                  <SelectItem value="ssh">SSH</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Auto Sync</Label>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">{autoSync ? 'Enabled' : 'Disabled'}<Button variant="outline" size="sm" onClick={()=>setAutoSync(!autoSync)}>{autoSync ? 'Disable' : 'Enable'}</Button></div>
            </div>
          </div>
          {authType === 'token' ? (
            <div className="space-y-2">
              <Label>Personal Access Token</Label>
              <Input type="password" placeholder="ghp_..." value={token} onChange={(e)=>setToken(e.target.value)} />
              <Alert><AlertDescription>
                Token is encrypted at rest and never returned by the API. Leave blank to keep the existing token.
              </AlertDescription></Alert>
            </div>
          ) : (
            <div className="space-y-2">
              <Label>SSH Private Key</Label>
              <Input type="password" placeholder="-----BEGIN PRIVATE KEY-----" value={privateKey} onChange={(e)=>setPrivateKey(e.target.value)} />
              <Alert><AlertDescription>
                Private key is encrypted at rest and never returned by the API. Leave blank to keep the existing key.
              </AlertDescription></Alert>
            </div>
          )}
          {lastCheck && (
            <Alert variant={lastCheck.ok ? 'default' : 'destructive'}>
              <AlertDescription>{checkMessage}</AlertDescription>
            </Alert>
          )}
        </div>
        <DialogFooter className="gap-2">
          {gitStatus?.repository_initialized && (<Button variant="destructive" onClick={()=>deinitMutation.mutate()} disabled={deinitMutation.isPending}>Stop using Git</Button>)}
          <Button onClick={()=>saveMutation.mutate()} disabled={saveMutation.isPending}>{saveMutation.isPending ? 'Saving...' : 'Save'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
